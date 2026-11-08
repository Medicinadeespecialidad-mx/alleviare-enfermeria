-- Alleviare · esquema para Supabase
-- Pégalo completo en Supabase > SQL Editor > New query > Run.
-- Las tablas quedan cerradas (seguridad por filas sin políticas): la app solo entra por las funciones api_*,
-- que exigen una sesión válida y revisan los permisos que Dirección otorga a cada persona.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.staff (
  id uuid primary key default gen_random_uuid(),
  nombre text not null,
  tipo text not null default 'enfermeria' check (tipo in ('enfermeria','medico','otro')),
  cedula text unique,
  puesto text,
  telefono text,
  fecha_nac date,
  usuario text unique,
  pin_hash text not null default '',
  es_direccion boolean not null default false,
  permisos text[] not null default '{}',
  activa boolean not null default true,
  intentos int not null default 0,
  bloqueada_hasta timestamptz,
  creado timestamptz not null default now()
);

create table if not exists public.sessions (
  token uuid primary key default gen_random_uuid(),
  staff_id uuid not null references public.staff(id) on delete cascade,
  expira timestamptz not null default now() + interval '14 hours'
);

create table if not exists public.docs (
  col text not null,
  id text not null,
  data jsonb not null,
  deleted boolean not null default false,
  updated_at timestamptz not null default clock_timestamp(),
  updated_by text,
  primary key (col, id)
);
create index if not exists docs_updated_idx on public.docs (updated_at);

create table if not exists public.bitacora (
  id bigserial primary key,
  t timestamptz not null default now(),
  staff text,
  accion text,
  col text,
  doc_id text
);

alter table public.staff enable row level security;
alter table public.sessions enable row level security;
alter table public.docs enable row level security;
alter table public.bitacora enable row level security;

-- ---------- utilidades internas ----------
create or replace function public._me(p_token uuid)
returns public.staff language plpgsql security definer set search_path = public, extensions as $$
declare s public.staff;
begin
  select st.* into s from public.sessions se join public.staff st on st.id = se.staff_id
   where se.token = p_token and se.expira > now() and st.activa and st.pin_hash <> '';
  if s.id is null then raise exception 'sesion_invalida'; end if;
  return s;
end $$;

create or replace function public._can(s public.staff, p text)
returns boolean language sql immutable as $$ select s.es_direccion or p = any(s.permisos) $$;

create or replace function public._perfil(s public.staff)
returns json language sql stable as $$
  select json_build_object('id', s.id, 'nombre', s.nombre, 'cedula', s.cedula, 'puesto', s.puesto, 'tipo', s.tipo,
    'direccion', s.es_direccion,
    'permisos', case when s.es_direccion then array['enfermeria','coordinacion','inventario','administracion'] else s.permisos end)
$$;

create or replace function public._session(p_staff uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare t uuid; s public.staff;
begin
  delete from public.sessions where expira < now();
  insert into public.sessions (staff_id) values (p_staff) returning token into t;
  select * into s from public.staff where id = p_staff;
  return json_build_object('token', t, 'staff', public._perfil(s));
end $$;

create or replace function public._check_login(s public.staff, p_pass text)
returns void language plpgsql security definer set search_path = public, extensions as $$
begin
  if s.id is null then raise exception 'no_encontrada'; end if;
  if s.bloqueada_hasta is not null and s.bloqueada_hasta > now() then raise exception 'bloqueada'; end if;
  if crypt(coalesce(p_pass,''), s.pin_hash) <> s.pin_hash then
    update public.staff set intentos = intentos + 1,
      bloqueada_hasta = case when intentos + 1 >= 5 then now() + interval '15 minutes' else null end
     where id = s.id;
    raise exception 'pin_incorrecto';
  end if;
  update public.staff set intentos = 0, bloqueada_hasta = null where id = s.id;
  insert into public.bitacora (staff, accion) values (s.nombre, 'entrada');
end $$;

-- ---------- acceso ----------
drop function if exists public.api_staff_list();
create function public.api_staff_list()
returns table (id uuid, nombre text, enf boolean) language sql security definer set search_path = public as $$
  select id, nombre, 'enfermeria' = any(permisos) from public.staff where activa and pin_hash <> '' and not es_direccion order by nombre
$$;

create or replace function public.api_register(p_nombre text, p_tipo text, p_cedula text, p_puesto text, p_telefono text, p_fecha date, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare s public.staff; ced text := nullif(trim(coalesce(p_cedula,'')), ''); tel text := regexp_replace(coalesce(p_telefono,''), '\D', '', 'g');
begin
  if coalesce(p_pin,'') !~ '^[0-9]{4}$' then raise exception 'pin_invalido'; end if;
  if length(trim(coalesce(p_nombre,''))) < 5 then raise exception 'nombre_invalido'; end if;
  if p_tipo not in ('enfermeria','medico','otro') then raise exception 'tipo_invalido'; end if;
  if p_tipo in ('enfermeria','medico') and coalesce(ced,'') !~ '^[0-9]{5,10}$' then raise exception 'cedula_invalida'; end if;
  if p_tipo = 'otro' and length(trim(coalesce(p_puesto,''))) < 3 then raise exception 'puesto_invalido'; end if;
  if length(tel) < 10 then raise exception 'telefono_invalido'; end if;
  if ced is not null then select * into s from public.staff where cedula = ced;
  else select * into s from public.staff where cedula is null and telefono = tel and not es_direccion; end if;
  if s.id is not null and s.pin_hash <> '' then raise exception 'ya_registrada'; end if;
  if s.id is not null and not s.activa then raise exception 'cuenta_inactiva'; end if;
  if s.id is null then
    insert into public.staff (nombre, tipo, cedula, puesto, telefono, fecha_nac, pin_hash)
    values (trim(p_nombre), p_tipo, ced, nullif(trim(coalesce(p_puesto,'')),''), tel, p_fecha, crypt(p_pin, gen_salt('bf'))) returning * into s;
  else
    update public.staff set nombre = trim(p_nombre), tipo = p_tipo, puesto = nullif(trim(coalesce(p_puesto,'')),''), telefono = tel, fecha_nac = p_fecha,
      pin_hash = crypt(p_pin, gen_salt('bf')), intentos = 0, bloqueada_hasta = null
     where id = s.id returning * into s;
  end if;
  insert into public.bitacora (staff, accion) values (s.nombre, 'registro');
  return public._session(s.id);
end $$;

create or replace function public.api_login(p_id uuid, p_pin text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare s public.staff;
begin
  select * into s from public.staff where id = p_id and activa and pin_hash <> '' and not es_direccion;
  perform public._check_login(s, p_pin);
  return public._session(s.id);
end $$;

create or replace function public.api_dir_login(p_usuario text, p_pass text)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare s public.staff;
begin
  select * into s from public.staff where es_direccion and activa and lower(regexp_replace(trim(usuario), '\s+', ' ', 'g')) = lower(regexp_replace(trim(coalesce(p_usuario,'')), '\s+', ' ', 'g'));
  perform public._check_login(s, p_pass);
  return public._session(s.id);
end $$;

create or replace function public.api_dir_password(p_token uuid, p_actual text, p_nueva text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff;
begin
  me := public._me(p_token);
  if not me.es_direccion then raise exception 'sin_permiso'; end if;
  if crypt(coalesce(p_actual,''), me.pin_hash) <> me.pin_hash then raise exception 'pin_incorrecto'; end if;
  if length(coalesce(p_nueva,'')) < 8 then raise exception 'contrasena_corta'; end if;
  update public.staff set pin_hash = crypt(p_nueva, gen_salt('bf')) where id = me.id;
end $$;

create or replace function public.api_logout(p_token uuid)
returns void language sql security definer set search_path = public as $$
  delete from public.sessions where token = p_token
$$;

-- ---------- datos ----------
create or replace function public.api_pull(p_token uuid, p_since timestamptz)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff; clinico boolean; out json;
begin
  me := public._me(p_token);
  clinico := public._can(me, 'enfermeria') or public._can(me, 'coordinacion');
  if not (clinico or public._can(me, 'inventario') or public._can(me, 'administracion')) then
    return json_build_object('now', clock_timestamp(), 'me', public._perfil(me), 'docs', '[]'::json);
  end if;
  select json_build_object('now', clock_timestamp(), 'me', public._perfil(me),
    'pend_borrado', (select coalesce(json_agg(b.col || '/' || b.doc_id), '[]'::json) from public.borrado_solicitudes b where b.estado = 'pendiente'),
    'docs', coalesce(json_agg(json_build_object('col', d.col, 'id', d.id, 'deleted', d.deleted, 'u', d.updated_at,
      'data', case
        when clinico then d.data
        when d.col = 'patients' then jsonb_build_object('id', d.data->'id', 'nombre', d.data->'nombre', 'estado', d.data->'estado', 'responsable', d.data->'responsable', 'fechaNac', d.data->'fechaNac', 'domicilio', d.data->'domicilio', 'nivel', d.data->'nivel', 'telResp', d.data->'telResp', 'alta', d.data->'alta', 'porCompletar', d.data->'porCompletar')
        when d.col = 'shifts' then jsonb_build_object('id', d.data->'id', 'patientId', d.data->'patientId', 'fecha', d.data->'fecha', 'turno', d.data->'turno', 'enfermera', d.data->'enfermera', 'servicio', d.data->'servicio', 'insumos', d.data->'insumos', 'bomba', jsonb_build_object('usada', d.data->'bomba'->'usada'), 'cerrado', d.data->'cerrado', 'creadoEn', d.data->'creadoEn', 'updatedAt', d.data->'updatedAt')
        else d.data end)), '[]'::json))
  into out
  from public.docs d
  where d.updated_at > coalesce(p_since, 'epoch'::timestamptz)
    and (clinico or d.col in ('patients','shifts','items','moves','config','ventas'))
    and (d.col <> 'ventas' or public._can(me, 'administracion'));
  return out;
end $$;

create or replace function public.api_put(p_token uuid, p_col text, p_id text, p_data jsonb)
returns timestamptz language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff; t timestamptz := clock_timestamp(); ok boolean;
begin
  me := public._me(p_token);
  ok := case p_col
    when 'patients' then public._can(me,'enfermeria') or public._can(me,'coordinacion')
    when 'shifts'   then public._can(me,'enfermeria') or public._can(me,'coordinacion')
    when 'items'    then public._can(me,'enfermeria') or public._can(me,'inventario') or public._can(me,'coordinacion') or public._can(me,'administracion')
    when 'moves'    then public._can(me,'enfermeria') or public._can(me,'inventario') or public._can(me,'coordinacion') or public._can(me,'administracion')
    when 'config'   then public._can(me,'administracion')
    when 'ventas'   then public._can(me,'administracion')
    else false end;
  if not ok then raise exception 'sin_permiso'; end if;
  insert into public.docs (col, id, data, deleted, updated_at, updated_by)
  values (p_col, p_id, p_data, false, t, me.nombre)
  on conflict (col, id) do update set data = excluded.data, deleted = false, updated_at = t, updated_by = me.nombre;
  insert into public.bitacora (staff, accion, col, doc_id) values (me.nombre, 'guardar', p_col, p_id);
  return t;
end $$;

create or replace function public.api_delete(p_token uuid, p_col text, p_id text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff;
begin
  me := public._me(p_token);
  if not ((p_col = 'items' and (public._can(me,'inventario') or public._can(me,'enfermeria') or public._can(me,'administracion')))
       or (p_col = 'ventas' and public._can(me,'administracion'))) then raise exception 'sin_permiso'; end if;
  update public.docs set deleted = true, updated_at = clock_timestamp(), updated_by = me.nombre where col = p_col and id = p_id;
  insert into public.bitacora (staff, accion, col, doc_id) values (me.nombre, 'borrar', p_col, p_id);
end $$;

-- ---------- Aviso de privacidad: firma a distancia con enlace de un solo uso ----------
create table if not exists public.aviso_links (
  token uuid primary key default gen_random_uuid(),
  pid text not null,
  creado_por text not null,
  creado timestamptz not null default now(),
  expira timestamptz not null default now() + interval '7 days',
  usado timestamptz
);
alter table public.aviso_links enable row level security;

create or replace function public.api_aviso_link(p_token uuid, p_pid text)
returns uuid language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff; t uuid;
begin
  me := public._me(p_token);
  if not (public._can(me,'enfermeria') or public._can(me,'coordinacion')) then raise exception 'sin_permiso'; end if;
  if not exists (select 1 from public.docs where col = 'patients' and id = p_pid and not deleted) then raise exception 'no_encontrado'; end if;
  update public.aviso_links set expira = now() where pid = p_pid and usado is null and expira > now();
  insert into public.aviso_links (pid, creado_por) values (p_pid, me.nombre) returning token into t;
  insert into public.bitacora (staff, accion, col, doc_id) values (me.nombre, 'enlace aviso de privacidad', 'patients', p_pid);
  return t;
end $$;

-- Lo que ve el familiar: solo el nombre del paciente y los datos de contacto del aviso.
create or replace function public.api_aviso_get(p_link uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare l public.aviso_links; d jsonb;
begin
  select * into l from public.aviso_links where token = p_link;
  if l.token is null or l.expira < now() then raise exception 'enlace_vencido'; end if;
  if l.usado is not null then raise exception 'enlace_usado'; end if;
  select data into d from public.docs where col = 'patients' and id = l.pid and not deleted;
  if d is null then raise exception 'enlace_vencido'; end if;
  return json_build_object('paciente', d->>'nombre', 'responsable', d->>'responsable',
    'cfg', (select data from public.docs where col = 'config' and id = 'aviso' and not deleted));
end $$;

create or replace function public.api_aviso_firmar(p_link uuid, p_nombre text, p_relacion text, p_parentesco text, p_no_secundarias boolean, p_firma text)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare l public.aviso_links; t timestamptz := clock_timestamp(); av jsonb;
begin
  select * into l from public.aviso_links where token = p_link for update;
  if l.token is null or l.expira < now() then raise exception 'enlace_vencido'; end if;
  if l.usado is not null then raise exception 'enlace_usado'; end if;
  if length(trim(coalesce(p_nombre,''))) < 5 then raise exception 'nombre_invalido'; end if;
  if coalesce(p_firma,'') !~ '^data:image/(jpeg|png);base64,' or length(p_firma) > 300000 then raise exception 'firma_invalida'; end if;
  av := jsonb_build_object('firmadoPor', trim(p_nombre), 'relacion', coalesce(p_relacion,''), 'parentesco', coalesce(p_parentesco,''),
    'noSecundarias', coalesce(p_no_secundarias,false), 'firma', p_firma, 'fecha', t, 'enfermera', 'Firma a distancia (enlace de ' || l.creado_por || ')', 'version', '2026-11', 'remoto', true);
  update public.docs set data = data || jsonb_build_object('aviso', av, 'privacidad', 'Sí',
      'audit', coalesce(data->'audit','[]'::jsonb) || jsonb_build_array(jsonb_build_object('t', t, 'who', trim(p_nombre), 'what', 'Aviso de privacidad firmado a distancia por enlace'))),
    updated_at = t, updated_by = trim(p_nombre) || ' (enlace)'
  where col = 'patients' and id = l.pid;
  update public.aviso_links set usado = t where token = p_link;
  insert into public.bitacora (staff, accion, col, doc_id) values (trim(p_nombre), 'firmó aviso de privacidad por enlace', 'patients', l.pid);
end $$;

-- ---------- Certificado de defunción: formulario público para la familia ----------
-- Se guarda en la colección de Administración (solo Administración y Dirección la leen).
create or replace function public.api_defuncion_enviar(p_data jsonb)
returns text language plpgsql security definer set search_path = public, extensions as $$
declare i text := 'def_' || replace(gen_random_uuid()::text, '-', '');
begin
  if p_data is null or jsonb_typeof(p_data) <> 'object' or length(p_data::text) > 20000 then raise exception 'datos_invalidos'; end if;
  if length(trim(coalesce(p_data->>'nombre',''))) < 5 then raise exception 'nombre_invalido'; end if;
  if (select count(*) from public.docs where col = 'ventas' and id like 'def\_%' and updated_at > now() - interval '10 minutes') > 20 then raise exception 'demasiados_envios'; end if;
  insert into public.docs (col, id, data, updated_at, updated_by)
  values ('ventas', i, jsonb_build_object('id', i, 'doc', 'defuncion', 'origen', 'familia', 'recibido', clock_timestamp(), 'form', p_data,
    'nombre', trim(p_data->>'nombre'), 'fecha', p_data->>'fecha', 'hora', p_data->>'hora', 'cobrado', 'No'), clock_timestamp(), 'Familia (formulario)');
  insert into public.bitacora (staff, accion, col, doc_id) values ('Familia (formulario)', 'datos de certificado de defunción', 'ventas', i);
  return i;
end $$;

-- ---------- Borrado de registros: el personal solicita, solo Dirección autoriza ----------
create table if not exists public.borrado_solicitudes (
  id bigserial primary key,
  col text not null,
  doc_id text not null,
  resumen text,
  motivo text not null,
  solicitado_por text not null,
  creado timestamptz not null default now(),
  estado text not null default 'pendiente' check (estado in ('pendiente','autorizada','rechazada')),
  resuelto_por text,
  resuelto timestamptz
);
alter table public.borrado_solicitudes enable row level security;

create or replace function public.api_borrado_solicitar(p_token uuid, p_col text, p_id text, p_motivo text, p_resumen text)
returns bigint language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff; i bigint;
begin
  me := public._me(p_token);
  if p_col = 'patients' then
    if not (public._can(me,'enfermeria') or public._can(me,'coordinacion') or public._can(me,'administracion')) then raise exception 'sin_permiso'; end if;
  elsif p_col = 'ventas' then
    if not public._can(me,'administracion') or p_id not like 'venta\_%' then raise exception 'sin_permiso'; end if;
  else raise exception 'sin_permiso'; end if;
  if length(trim(coalesce(p_motivo,''))) < 4 then raise exception 'motivo_requerido'; end if;
  if not exists (select 1 from public.docs where col = p_col and id = p_id and not deleted) then raise exception 'no_encontrado'; end if;
  select id into i from public.borrado_solicitudes where col = p_col and doc_id = p_id and estado = 'pendiente';
  if i is not null then return i; end if;
  insert into public.borrado_solicitudes (col, doc_id, resumen, motivo, solicitado_por) values (p_col, p_id, left(p_resumen, 300), trim(p_motivo), me.nombre) returning id into i;
  insert into public.bitacora (staff, accion, col, doc_id) values (me.nombre, 'solicitó borrado: ' || trim(p_motivo), p_col, p_id);
  return i;
end $$;

create or replace function public.api_borrado_list(p_token uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff;
begin
  me := public._me(p_token);
  if not me.es_direccion then raise exception 'sin_permiso'; end if;
  return (select coalesce(json_agg(json_build_object('id', id, 'col', col, 'docId', doc_id, 'resumen', resumen, 'motivo', motivo, 'por', solicitado_por, 'creado', creado, 'estado', estado, 'resueltoPor', resuelto_por, 'resuelto', resuelto) order by (estado = 'pendiente') desc, creado desc), '[]'::json)
    from (select * from public.borrado_solicitudes where estado = 'pendiente' or resuelto > now() - interval '30 days') s);
end $$;

-- Borrado lógico: el registro se oculta en la plataforma pero se conserva en la base (NOM-004 y bitácora).
create or replace function public.api_borrado_resolver(p_token uuid, p_sol bigint, p_autorizar boolean)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff; s public.borrado_solicitudes; t timestamptz := clock_timestamp();
begin
  me := public._me(p_token);
  if not me.es_direccion then raise exception 'sin_permiso'; end if;
  select * into s from public.borrado_solicitudes where id = p_sol and estado = 'pendiente' for update;
  if s.id is null then raise exception 'no_encontrada'; end if;
  update public.borrado_solicitudes set estado = case when p_autorizar then 'autorizada' else 'rechazada' end, resuelto_por = me.nombre, resuelto = t where id = s.id;
  if p_autorizar then
    update public.docs set deleted = true, updated_at = t, updated_by = me.nombre where col = s.col and id = s.doc_id;
    if s.col = 'patients' then
      update public.docs set deleted = true, updated_at = t, updated_by = me.nombre where col = 'shifts' and data->>'patientId' = s.doc_id;
    end if;
  end if;
  insert into public.bitacora (staff, accion, col, doc_id) values (me.nombre, case when p_autorizar then 'autorizó borrado' else 'rechazó borrado' end, s.col, s.doc_id);
end $$;

-- ---------- Alta rápida de paciente desde Administración / Dirección (la enfermera asignada completa el expediente) ----------
create or replace function public.api_paciente_alta(p_token uuid, p_id text, p_data jsonb)
returns timestamptz language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff; t timestamptz := clock_timestamp(); ex public.docs; d jsonb;
begin
  me := public._me(p_token);
  if not public._can(me,'administracion') then raise exception 'sin_permiso'; end if;
  if p_id !~ '^p[a-z0-9_]{3,40}$' or length(trim(coalesce(p_data->>'nombre',''))) < 3 then raise exception 'datos_invalidos'; end if;
  select * into ex from public.docs where col = 'patients' and id = p_id;
  if ex.id is not null and (ex.deleted or coalesce(ex.data->>'porCompletar','') <> 'true') then raise exception 'ya_completado'; end if;
  d := jsonb_build_object('id', p_id, 'nombre', trim(p_data->>'nombre'), 'domicilio', p_data->'domicilio', 'responsable', p_data->'responsable', 'telResp', p_data->'telResp',
    'alta', jsonb_build_object('fecha', p_data->'alta'->'fecha', 'hora', p_data->'alta'->'hora', 'enfermera', p_data->'alta'->'enfermera', 'modalidad', p_data->'alta'->'modalidad', 'detalle', p_data->'alta'->'detalle', 'notas', p_data->'alta'->'notas', 'por', me.nombre, 't', t),
    'porCompletar', true, 'estado', 'activo', 'nivel', 'intermedio', 'tipoAtencion', 'Primera vez', 'fechaRegistro', to_char(t at time zone 'America/Mexico_City', 'YYYY-MM-DD'),
    'meds', '[]'::jsonb, 'indicaciones', '[]'::jsonb, 'creadoPor', me.nombre, 'creadoEn', t,
    'audit', jsonb_build_array(jsonb_build_object('t', t, 'who', me.nombre, 'what', 'Alta para visita a domicilio; asignada a ' || coalesce(p_data->'alta'->>'enfermera','—'))));
  if ex.id is not null then d := ex.data || (d - 'audit' - 'creadoPor' - 'creadoEn' - 'fechaRegistro'); end if;
  insert into public.docs (col, id, data, deleted, updated_at, updated_by) values ('patients', p_id, d, false, t, me.nombre)
  on conflict (col, id) do update set data = excluded.data, updated_at = t, updated_by = me.nombre;
  insert into public.bitacora (staff, accion, col, doc_id) values (me.nombre, 'alta de paciente para visita', 'patients', p_id);
  return t;
end $$;

-- ---------- Dirección: personal y permisos ----------
create or replace function public.api_staff_all(p_token uuid)
returns json language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff;
begin
  me := public._me(p_token);
  if not me.es_direccion then raise exception 'sin_permiso'; end if;
  return (select coalesce(json_agg(json_build_object('id', id, 'nombre', nombre, 'tipo', tipo, 'cedula', cedula, 'puesto', puesto, 'telefono', telefono,
    'fechaNac', fecha_nac, 'permisos', permisos, 'activa', activa, 'tienePin', pin_hash <> '', 'creadoEn', creado, 'bloqueada', bloqueada_hasta > now()) order by nombre), '[]'::json)
    from public.staff where not es_direccion);
end $$;

create or replace function public.api_staff_update(p_token uuid, p_id uuid, p_activa boolean, p_reset boolean, p_permisos text[])
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff;
begin
  me := public._me(p_token);
  if not me.es_direccion then raise exception 'sin_permiso'; end if;
  if p_permisos is not null and not (p_permisos <@ array['enfermeria','coordinacion','inventario','administracion']) then raise exception 'permiso_invalido'; end if;
  update public.staff set
    activa = coalesce(p_activa, activa),
    pin_hash = case when p_reset then '' else pin_hash end,
    intentos = case when p_reset then 0 else intentos end,
    bloqueada_hasta = case when p_reset then null else bloqueada_hasta end,
    permisos = coalesce(p_permisos, permisos)
  where id = p_id and not es_direccion;
  if p_reset or p_activa = false then delete from public.sessions where staff_id = p_id; end if;
  insert into public.bitacora (staff, accion, doc_id) values (me.nombre, 'permisos', p_id::text);
end $$;

-- Elimina la cuenta de una persona. Sus turnos, firmas y movimientos se conservan
-- (el expediente guarda el nombre como texto; NOM-004-SSA3-2012 exige conservarlo).
create or replace function public.api_staff_delete(p_token uuid, p_id uuid)
returns void language plpgsql security definer set search_path = public, extensions as $$
declare me public.staff; s public.staff;
begin
  me := public._me(p_token);
  if not me.es_direccion then raise exception 'sin_permiso'; end if;
  select * into s from public.staff where id = p_id and not es_direccion;
  if s.id is null then raise exception 'no_encontrada'; end if;
  delete from public.sessions where staff_id = p_id;
  delete from public.staff where id = p_id;
  insert into public.bitacora (staff, accion, doc_id) values (me.nombre, 'eliminó cuenta: ' || s.nombre || coalesce(' (cédula ' || s.cedula || ')', ''), p_id::text);
end $$;

-- Solo las funciones api_* son públicas.
revoke all on function public._me(uuid) from public, anon, authenticated;
revoke all on function public._session(uuid) from public, anon, authenticated;
revoke all on function public._check_login(public.staff, text) from public, anon, authenticated;
grant execute on function public.api_staff_list(), public.api_register(text,text,text,text,text,date,text), public.api_login(uuid,text),
  public.api_dir_login(text,text), public.api_dir_password(uuid,text,text), public.api_logout(uuid), public.api_pull(uuid,timestamptz),
  public.api_put(uuid,text,text,jsonb), public.api_delete(uuid,text,text), public.api_staff_all(uuid),
  public.api_staff_update(uuid,uuid,boolean,boolean,text[]), public.api_staff_delete(uuid,uuid), public.api_aviso_link(uuid,text), public.api_aviso_get(uuid),
  public.api_aviso_firmar(uuid,text,text,text,boolean,text), public.api_defuncion_enviar(jsonb),
  public.api_borrado_solicitar(uuid,text,text,text,text), public.api_borrado_list(uuid), public.api_borrado_resolver(uuid,bigint,boolean), public.api_paciente_alta(uuid,text,jsonb) to anon, authenticated;
