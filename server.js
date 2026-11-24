const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'reencuentro.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS casos (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS avistamientos (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS mensajes (id TEXT PRIMARY KEY, owner_id TEXT NOT NULL, payload TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id));
CREATE TABLE IF NOT EXISTS opiniones (owner_id TEXT PRIMARY KEY, payload TEXT NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY(owner_id) REFERENCES users(id));
CREATE INDEX IF NOT EXISTS idx_casos_created ON casos(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_avist_created ON avistamientos(created_at DESC);
`);
const q = {
 userByEmail: db.prepare('SELECT * FROM users WHERE email=?'),
 userById: db.prepare('SELECT * FROM users WHERE id=?'),
 insertUser: db.prepare('INSERT INTO users(id,name,email,password_hash,is_admin,created_at) VALUES(?,?,?,?,?,?)'),
 listCases: db.prepare('SELECT payload FROM casos ORDER BY created_at DESC'),
 listAv: db.prepare('SELECT payload FROM avistamientos ORDER BY created_at DESC'),
 listMessages: db.prepare('SELECT owner_id,payload FROM mensajes ORDER BY created_at DESC'),
 listOpinions: db.prepare('SELECT payload FROM opiniones ORDER BY created_at DESC'),
 getCase: db.prepare('SELECT * FROM casos WHERE id=?'),
 upsertCase: db.prepare('INSERT INTO casos(id,owner_id,payload,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload'),
 upsertAv: db.prepare('INSERT INTO avistamientos(id,owner_id,payload,created_at) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload'),
 delCase: db.prepare('DELETE FROM casos WHERE id=?'),
 delAv: db.prepare('DELETE FROM avistamientos WHERE id=?'),
 insertMessage: db.prepare('INSERT INTO mensajes(id,owner_id,payload,created_at) VALUES(?,?,?,?)'),
 upsertOpinion: db.prepare('INSERT INTO opiniones(owner_id,payload,created_at) VALUES(?,?,?) ON CONFLICT(owner_id) DO UPDATE SET payload=excluded.payload,created_at=excluded.created_at')
};
const uid = () => require('crypto').randomUUID();
const now = () => new Date().toISOString();
const cleanUser = u => ({ id:u.id, name:u.name, email:u.email, admin:!!u.is_admin });
const requireAuth = (req,res,next) => req.session.userId ? next() : res.status(401).json({error:'Inicia sesión para continuar.'});
const requireAdmin = (req,res,next) => {
 const u=q.userById.get(req.session.userId);
 if (!u || !u.is_admin) return res.status(403).json({error:'Acceso exclusivo para moderadores.'});
 next();
};
app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false, crossOriginEmbedderPolicy:false}));
app.use(express.json({limit:'5mb'}));
app.use(session({
 store:new SQLiteStore({db:'sessions.sqlite',dir:DATA_DIR}),
 secret:process.env.SESSION_SECRET || 'CAMBIA-ESTA-CLAVE-ANTES-DE-PUBLICAR-REENCUENTRO-SEGURO',
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:7*24*60*60*1000}
}));
const authLimiter=rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false});
app.use('/api/auth',authLimiter);
app.use('/api',(req,res,next)=>{
 res.set('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
 res.set('Pragma','no-cache');
 res.set('Expires','0');
 next();
});

app.get('/api/session',(req,res)=>{
 const u=req.session.userId && q.userById.get(req.session.userId);
 res.json({user:u?cleanUser(u):null});
});
app.post('/api/auth/register',(req,res)=>{
 const name=String(req.body.name||'').trim().slice(0,100);
 const email=String(req.body.email||'').trim().toLowerCase();
 const password=String(req.body.password||'');
 if(name.length<2) return res.status(400).json({error:'Escribe tu nombre.'});
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'Correo electrónico no válido.'});
 if(password.length<8) return res.status(400).json({error:'La contraseña debe tener al menos 8 caracteres.'});
 if(q.userByEmail.get(email)) return res.status(409).json({error:'Ya existe una cuenta con ese correo.'});
 const adminEmail=String(process.env.ADMIN_EMAIL||'').toLowerCase();
 const id=uid(), isAdmin=!!adminEmail && email===adminEmail;
 q.insertUser.run(id,name,email,bcrypt.hashSync(password,12),isAdmin?1:0,now());
 req.session.userId=id;
 res.status(201).json({user:cleanUser(q.userById.get(id))});
});
app.post('/api/auth/login',(req,res)=>{
 const email=String(req.body.email||'').trim().toLowerCase();
 const u=q.userByEmail.get(email);
 if(!u || !bcrypt.compareSync(String(req.body.password||''),u.password_hash))
   return res.status(401).json({error:'Correo o contraseña incorrectos.'});
 req.session.userId=u.id;res.json({user:cleanUser(u)});
});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get('/api/datos',requireAuth,(req,res)=>{
 const u=q.userById.get(req.session.userId), admin=!!u.is_admin;
 const casos=q.listCases.all().map(x=>JSON.parse(x.payload)).filter(c=>admin || c.moderacion==='aprobado' || c.creadoPor===u.id);
 const avistamientos=q.listAv.all().map(x=>JSON.parse(x.payload));
 const rows=q.listMessages.all();
 const buzon=admin ? rows.map(r=>({uid:r.owner_id,items:JSON.parse(r.payload)})) :
   rows.filter(r=>r.owner_id===u.id).map(r=>({uid:r.owner_id,items:JSON.parse(r.payload)}));
 const opiniones=admin ? q.listOpinions.all().map(x=>JSON.parse(x.payload)) :
   q.listOpinions.all().map(x=>JSON.parse(x.payload)).filter(o=>o.creadoPor===u.id);
 // Totales reales de toda la base (sin datos de ejemplo), para el resumen del inicio.
 const todos=q.listCases.all().map(x=>JSON.parse(x.payload)).filter(c=>!c.ejemplo&&c.moderacion!=='rechazado');
 const resumen={
  activos:todos.filter(c=>!['reunido','cerrado'].includes(c.estado)).length,
  reunidos:todos.filter(c=>c.estado==='reunido').length,
  avist:q.listAv.all().map(x=>JSON.parse(x.payload)).filter(a=>!a.ejemplo).length
 };
 res.json({casos,avistamientos,buzon,opiniones,resumen});
});
app.post('/api/casos',requireAuth,(req,res)=>{
 console.log('[POST casos]',req.session.userId,req.body&&req.body.id);
 const c=req.body||{}; if(!c.id || !['perdida','encontrada'].includes(c.tipo))return res.status(400).json({error:'Reporte incompleto.'});
 const old=q.getCase.get(c.id),u=q.userById.get(req.session.userId);
 if(old && old.owner_id!==u.id && !u.is_admin)return res.status(403).json({error:'No puedes modificar este reporte.'});
 const oldC=old?JSON.parse(old.payload):null;
 c.creadoPor=oldC?oldC.creadoPor:u.id;
 if(!oldC){
  // Un caso nuevo siempre entra en revisión, salvo que lo cree un moderador y lo marque como aprobado (p. ej. datos de ejemplo).
  c.moderacion=(u.is_admin&&c.moderacion==='aprobado')?'aprobado':'pendiente';
  c.creadoEn=now();
 }else if(!u.is_admin){
  // Quien no es moderador no puede cambiar el estado de moderación de su reporte.
  c.moderacion=oldC.moderacion;
 }
 q.upsertCase.run(c.id,c.creadoPor,JSON.stringify(c),c.creadoEn||now());res.json({ok:true});
});
app.post('/api/avistamientos',requireAuth,(req,res)=>{
 const a=req.body||{};if(!a.id)return res.status(400).json({error:'Avistamiento incompleto.'});
 a.creadoPor=req.session.userId;
 q.upsertAv.run(a.id,req.session.userId,JSON.stringify(a),a.creadoEn||now());res.json({ok:true});
});
app.delete('/api/casos/:id',requireAuth,(req,res)=>{
 const old=q.getCase.get(req.params.id);if(!old)return res.json({ok:true});
 const u=q.userById.get(req.session.userId);if(old.owner_id!==u.id&&!u.is_admin)return res.status(403).json({error:'No puedes eliminar este caso.'});
 q.delCase.run(req.params.id);res.json({ok:true});
});
app.delete('/api/avistamientos/:id',requireAuth,(req,res)=>{
 const old=db.prepare('SELECT owner_id FROM avistamientos WHERE id=?').get(req.params.id);
 if(old&&old.owner_id!==req.session.userId&&!q.userById.get(req.session.userId).is_admin)return res.status(403).json({error:'No puedes eliminar este registro.'});
 q.delAv.run(req.params.id);res.json({ok:true});
});
app.post('/api/mensajes',requireAuth,(req,res)=>{
 const item=req.body||{};if(!item.tipo)return res.status(400).json({error:'Mensaje incompleto.'});
 const id=uid(),owner=req.session.userId;
 const existing=db.prepare('SELECT payload FROM mensajes WHERE owner_id=? ORDER BY created_at DESC LIMIT 1').get(owner);
 const items=existing?JSON.parse(existing.payload):[];
 item.id=id;item.ts=now();item.de=owner;items.push(item);
 // Keep the complete private inbox for each account in one row.
 const last=db.prepare('SELECT id FROM mensajes WHERE owner_id=? ORDER BY created_at DESC LIMIT 1').get(owner);
 if(last)db.prepare('DELETE FROM mensajes WHERE owner_id=?').run(owner);
 q.insertMessage.run(id,owner,JSON.stringify(items),now());res.json({ok:true});
});
app.post('/api/opiniones',requireAuth,(req,res)=>{
 const o=req.body||{};o.creadoPor=req.session.userId;o.creadoEn=now();
 q.upsertOpinion.run(req.session.userId,JSON.stringify(o),now());res.json({ok:true});
});
app.post('/api/admin/casos/:id/moderacion',requireAuth,requireAdmin,(req,res)=>{
 const row=q.getCase.get(req.params.id);if(!row)return res.status(404).json({error:'Caso no encontrado.'});
 const c=JSON.parse(row.payload);if(!['aprobado','rechazado','pendiente'].includes(req.body.estado))return res.status(400).json({error:'Estado no válido.'});
 c.moderacion=req.body.estado;q.upsertCase.run(c.id,row.owner_id,JSON.stringify(c),c.creadoEn||now());res.json({ok:true});
});
app.use(express.static(path.join(__dirname,'public'),{
 setHeaders:(res,filePath)=>{
  if(filePath.endsWith('.html')||filePath.endsWith('.js')){
   res.setHeader('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
   res.setHeader('Pragma','no-cache');
   res.setHeader('Expires','0');
  }
 }
}));
app.get('*',(req,res)=>{
 res.set('Cache-Control','no-store, no-cache, must-revalidate, proxy-revalidate');
 res.sendFile(path.join(__dirname,'public','index.html'));
});
app.listen(PORT,()=>console.log(`Reencuentro Seguro disponible en http://localhost:${PORT}`));
