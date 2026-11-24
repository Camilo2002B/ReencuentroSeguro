# Reencuentro Seguro — MVP funcional

Aplicación web para reportar mascotas perdidas/encontradas, registrar avistamientos, buscar casos, recibir mensajes, actualizar estados y recopilar opiniones de validación.

## Requisitos
- Node.js 20 o superior
- npm

## Instalación local
1. Descomprime el proyecto.
2. Abre una terminal dentro de `ReencuentroSeguro`.
3. Ejecuta `npm install`.
4. Copia `.env.example` a `.env` y cambia `SESSION_SECRET` por una clave larga. Configura `ADMIN_EMAIL` con el correo que tendrá acceso al panel de moderación.
5. Ejecuta `npm start`.
6. Abre `http://localhost:3000`.

La primera persona que se registre con el correo definido en `ADMIN_EMAIL` tendrá rol de moderador. Los demás usuarios podrán crear cuentas normales.

## Qué queda funcional
- Registro e inicio de sesión con contraseñas cifradas.
- Sesiones persistentes.
- Base de datos SQLite compartida por todos los usuarios que accedan al mismo servidor.
- Reportes, avistamientos, mensajes y opiniones persistidos.
- Moderación de casos y panel de métricas.
- Filtros, alertas locales por preferencias, seguimiento de estados e historial.
- La información de contacto se guarda en la bandeja privada, no se muestra en las tarjetas públicas.

## Importante para usar desde varios celulares
La aplicación debe estar desplegada en un servidor accesible por internet y todos deben entrar por la misma URL. Ejecutarla en `localhost` solo permite acceder desde el computador que la ejecuta. Para producción se recomienda HTTPS, una clave `SESSION_SECRET` segura, copias de seguridad y almacenamiento persistente del directorio `data/`.

## Límites conocidos de esta versión
- El mapa es esquemático por sectores; no usa geolocalización ni mapas de navegación.
- Las alertas se consultan dentro de la aplicación; no se envían notificaciones push ni correos.
- Las fotos se almacenan como imagen comprimida en el registro; para despliegues grandes conviene migrar a almacenamiento de objetos.
- La aplicación es un MVP académico, no sustituye autoridades, veterinarias ni protocolos de protección animal.
- La moderación inicial se limita a aprobar/rechazar casos y revisar mensajes. Antes de usar datos personales reales a escala, el equipo debe formalizar política de tratamiento y canal de derechos de titulares conforme a la normativa aplicable.

## Seguridad
- Las cuentas tienen contraseña con hash bcrypt.
- Los endpoints de escritura requieren sesión.
- Solo el dueño del reporte o un moderador puede editarlo/eliminarlo.
- Solo moderadores pueden ver bandejas de mensajes y gestionar moderación.
- Configura HTTPS antes de publicar en internet.
