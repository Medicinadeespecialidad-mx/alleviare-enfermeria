# Alleviare · Plataforma de enfermería domiciliaria

Aplicación web (un solo archivo `index.html`) para el registro de turnos de enfermería, medicamentos, inventario por enfermera, coordinación y cotizaciones. Se publica gratis con GitHub Pages y guarda los datos en Supabase.

**Este repositorio es público y solo contiene código.** Nunca subas aquí contraseñas, datos de pacientes ni el archivo privado de Dirección.

## Secciones y permisos

| Sección | Quién entra |
|---|---|
| Enfermería | Personal autorizado con permiso *Enfermería* |
| Coordinación | Solo quien Dirección autorice |
| Inventario | Solo quien Dirección autorice |
| Administración | Solo quien Dirección autorice (ve cotizaciones, sin datos clínicos) |
| Dirección | Únicamente la cuenta de Dirección |

1. Cada persona se registra una vez (profesión: Enfermería o Médico(a) con cédula; Otro con puesto en la empresa) y crea una contraseña de 4 números.
2. Queda **pendiente de autorizar** hasta que Dirección marque a qué secciones tiene acceso.
3. Dirección puede desactivar cuentas y restablecer contraseñas.

## Puesta en marcha (una sola vez)

1. Crea un proyecto gratuito en [supabase.com](https://supabase.com) (región más cercana: `us-east-1` o `us-west-1`).
2. En **SQL Editor**, pega y ejecuta `supabase/schema.sql`.
3. En el mismo editor ejecuta el archivo privado `crear_direccion.sql` (no está en este repositorio; está en la carpeta privada del proyecto). Crea la cuenta de Dirección.
4. En **Project Settings → API** copia la *Project URL* y la clave *anon public* y ponlas en `config.js`.
5. En GitHub: **Settings → Pages → Branch: main / (root) → Save**. En un minuto la plataforma queda en `https://<usuario>.github.io/alleviare-enfermeria/`.
6. Entra a **Dirección** y cambia la contraseña inicial con **Cambiar mi contraseña**.

## Seguridad

- Las tablas tienen RLS activado y ninguna política: el navegador no puede leerlas directamente.
- Todo pasa por funciones `api_*` del servidor que validan la sesión y los permisos de cada persona.
- Contraseñas guardadas con bcrypt; bloqueo de 15 minutos tras 5 intentos fallidos; sesiones de 14 horas.
- Quien solo tiene Administración o Inventario no recibe datos clínicos de los pacientes.
- Sin conexión, los cambios se guardan en el teléfono y se envían al volver la señal.
