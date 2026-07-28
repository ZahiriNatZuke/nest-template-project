# Política de seguridad

## Reportar una vulnerabilidad

Usa el **reporte privado de vulnerabilidades** de GitHub, en la pestaña *Security* de este
repositorio (*Report a vulnerability*). Es un canal privado: el reporte no es público mientras se
trabaja en el arreglo.

**No abras un issue público** para algo explotable.

Se responde en cuanto es posible; es un proyecto mantenido por una persona en su tiempo, así que
no hay un compromiso de plazo.

## Qué es este repositorio

Una **plantilla**, no un servicio desplegado. El riesgo real no está en un servidor nuestro que
alguien pueda atacar, sino en lo que se propaga: cada proyecto que nace de aquí hereda estas
decisiones. Un default flojo en la plantilla se convierte en un default flojo en todos los
proyectos que la usen, y arreglarlo aquí no arregla los que ya salieron.

Por eso interesan especialmente los reportes sobre:

- **Autenticación y sesiones** — el manejo de la sesión, el 2FA y la rotación de credenciales.
- **Autorización** — que RBAC/ABAC no se pueda saltar por una ruta que olvidó su guard.
- **CSRF, throttling y cabeceras** — la configuración que viene puesta de fábrica.
- **Prisma y la capa de datos** — cualquier consulta que pueda construirse con entrada del
  usuario sin parametrizar.
- **Lo que corre en CI** con el token del workflow.

## Al usar la plantilla

- `.env.template` documenta las variables; **el `.env` real nunca se commitea**. El repositorio
  tiene secret scanning con *push protection*, así que GitHub rechaza el push de un secreto
  reconocible — pero eso es una red, no un permiso para descuidarse.
- Cambia **todos** los secretos de ejemplo antes de exponer nada: los de la plantilla son
  públicos por definición.
- Revisa la configuración de CORS, cookies y throttling para tu despliegue. Los valores que
  vienen son razonables para desarrollo, no una configuración de producción lista para usar.
