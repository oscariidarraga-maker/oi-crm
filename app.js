/* OI CRM sin conexión. Todo lo guardado en el dispositivo va cifrado con una clave derivada del PIN. */
'use strict';
const PASARELA = (window.OI_CONFIG || {}).pasarela || '';
const VERSION_APP = '4';
const ITERACIONES = 310000, MAX_FALLOS = 10, BLOQUEO_MS = 5 * 60000, ESPERA_ENVIO_MS = 7000;
const S = { clave: null, datos: null, cola: [], sesion: null, avisos: [], ultima: '', vista: 'dia', pila: [], filtro: 'todas', busqueda: '', red: 'ok', sincronizando: false, revocado: false, ocultoDesde: 0 };
const $ = id => document.getElementById(id);
const esc = v => String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const norm = v => String(v || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase();
const dos = n => String(n).padStart(2, '0');
const fechaLocal = d => d.getFullYear() + '-' + dos(d.getMonth() + 1) + '-' + dos(d.getDate());
const hoy = () => fechaLocal(new Date());
const masDias = n => { const d = new Date(); d.setDate(d.getDate() + n); return fechaLocal(d); };
const fmtDia = f => { if (!f) return 'Sin fecha'; const d = new Date(f + 'T12:00:00'); return isNaN(d) ? esc(f) : d.toLocaleDateString('es-CO', { day: 'numeric', month: 'short', year: f.slice(0, 4) === hoy().slice(0, 4) ? undefined : 'numeric' }); };
const fmtHora = iso => { const d = new Date(iso); return isNaN(d) ? '' : d.toLocaleString('es-CO', { day: 'numeric', month: 'short', hour: 'numeric', minute: '2-digit' }); };
const uuid = () => crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
const enlace = u => /^https?:\/\//i.test(String(u || '')) ? String(u) : '';
const mesDia = d => dos(d.getMonth() + 1) + '-' + dos(d.getDate());
/** Días hasta el próximo cumpleaños (MM-DD). El 29 de febrero se celebra el 28 en años no bisiestos. */
function diasCumple(md) {
  if (!/^\d{2}-\d{2}$/.test(md || '')) return null;
  const h = new Date(); h.setHours(0, 0, 0, 0);
  for (let i = 0; i < 2; i++) {
    const y = h.getFullYear() + i, bis = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0, m = md === '02-29' && !bis ? '02-28' : md;
    const d = new Date(y + '-' + m + 'T00:00:00'); if (d >= h) return Math.round((d - h) / 86400000);
  }
  return null;
}
const digitosWa = c => String((c && (c.w || (c.tel && c.tel[0]))) || '').replace(/\D/g, '');
const rellenar = (m, c) => String(m || '').replace(/\{\{\s*nombre\s*\}\}/gi, (c && c.nn) || String((c && c.n) || '').split(/\s+/)[0] || '').replace(/\{\{\s*nombre_completo\s*\}\}/gi, (c && c.n) || '');
const urlWa = (dig, texto) => 'https://wa.me/' + dig + (texto ? '?text=' + encodeURIComponent(texto) : '');
/** Llamar, WhatsApp y correo en un toque. WhatsApp abre la conversación con el texto listo; el envío lo haces tú. */
function botonesContacto(c, contexto) {
  if (!c) return '';
  const dig = digitosWa(c);
  return (c.tel && c.tel[0] ? '<a class="b" href="tel:' + esc(c.tel[0]) + '">Llamar</a>' : '') + (dig.length >= 8 ? '<button class="b" data-a="wa" data-id="' + esc(c.id) + '" data-ctx="' + esc(contexto || '') + '">WhatsApp</button>' : '') + (c.mail && c.mail[0] ? '<a class="b" href="mailto:' + esc(c.mail[0]) + '">Correo</a>' : '');
}
const etqInteres = p => p ? '<span class="etq' + (p >= 60 ? ' oro' : '') + '">Interés ' + p + '</span>' : '';

/* ---------- Almacén cifrado ---------- */
let bd = null;
function abrirBd() {
  if (bd) return Promise.resolve(bd);
  return new Promise((ok, mal) => { const r = indexedDB.open('oicrm', 1); r.onupgradeneeded = () => r.result.createObjectStore('kv'); r.onsuccess = () => { bd = r.result; ok(bd); }; r.onerror = () => mal(r.error); });
}
function kv(modo, fn) { return abrirBd().then(b => new Promise((ok, mal) => { const t = b.transaction('kv', modo), r = fn(t.objectStore('kv')); t.oncomplete = () => ok(r && r.result); t.onerror = () => mal(t.error); })); }
const kvLeer = k => kv('readonly', s => s.get(k));
const kvPoner = (k, v) => kv('readwrite', s => s.put(v, k));
const kvVaciar = () => kv('readwrite', s => s.clear());
async function derivar(pin, sal) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(pin), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: sal, iterations: ITERACIONES, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function guardar(k, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cifrado = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, S.clave, new TextEncoder().encode(JSON.stringify(obj)));
  await kvPoner(k, { iv, c: cifrado });
}
async function leer(k, clave) {
  const v = await kvLeer(k); if (!v) return null;
  return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: v.iv }, clave || S.clave, v.c)));
}
const guardarCola = () => guardar('cola', { cola: S.cola, avisos: S.avisos });

/* ---------- Pasarela ---------- */
async function llamar(cuerpo) {
  const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 90000);
  try {
    const r = await fetch(PASARELA, { method: 'POST', headers: { 'Content-Type': 'text/plain;charset=utf-8' }, body: JSON.stringify(cuerpo), redirect: 'follow', signal: ctl.signal, credentials: 'omit' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    return await r.json();
  } finally { clearTimeout(t); }
}
let temporizador = null;
function programarEnvio() { clearTimeout(temporizador); temporizador = setTimeout(sincronizar, ESPERA_ENVIO_MS); }
async function sincronizar() {
  if (!S.clave || !S.sesion || S.sincronizando || S.revocado) return;
  if (navigator.onLine === false) { S.red = 'fuera'; pintarEstado(); return; }
  S.sincronizando = true; pintarEstado();
  try {
    const pend = S.cola.filter(c => c.estado === 'pendiente').slice(0, 100);
    if (pend.length) {
      const r = await llamar({ accion: 'subir', token: S.sesion.token, cambios: pend.map(c => ({ id: c.id, accion: c.accion, fecha: c.fecha, datos: c.datos })) });
      if (r.error === 'NO_AUTORIZADO') { S.revocado = true; throw new Error('revocado'); }
      if (!r.ok) throw new Error(r.error);
      r.aceptados.forEach(id => { const c = S.cola.find(x => x.id === id); if (c) c.estado = 'enviado'; });
      await guardarCola();
    }
    const r2 = await llamar({ accion: 'bajar', token: S.sesion.token, version: S.datos && S.datos.version || '' });
    if (r2.error === 'NO_AUTORIZADO') { S.revocado = true; throw new Error('revocado'); }
    if (!r2.ok) throw new Error(r2.error);
    if (r2.cambios) { S.datos = r2.datos; await guardar('datos', S.datos); conciliar(); await guardarCola(); }
    S.ultima = new Date().toISOString(); await guardar('ultima', S.ultima);
    S.red = 'ok';
  } catch (e) {
    S.red = S.revocado ? 'revocado' : 'fuera';
  } finally {
    S.sincronizando = false; refrescar();
  }
}
/** Lo que el CRM ya resolvió sale de la cola. Una novedad se muestra: nunca se pierde en silencio. */
function conciliar() {
  const res = {}; (S.datos.resultados || []).forEach(r => { res[r.id] = r; });
  S.cola = S.cola.filter(c => {
    const r = res[c.id]; if (!r) return true;
    if (r.e !== 'OK') S.avisos.push({ id: c.id, tipo: r.e, texto: describir(c), motivo: r.m, fecha: new Date().toISOString() });
    return false;
  });
}
function describir(c) {
  const t = (S.datos && S.datos.tareas || []).find(x => x.id === c.datos.id);
  if (c.accion === 'CERRAR_TAREA') return 'Cerrar tarea' + (t ? ': ' + t.d : '');
  if (c.accion === 'REPROGRAMAR_TAREA') return 'Reprogramar al ' + c.datos.fecha + (t ? ': ' + t.d : '');
  if (c.accion === 'CREAR_TAREA') return 'Nueva tarea: ' + c.datos.descripcion;
  const nc = id => { const x = (S.datos && S.datos.clientes || []).find(k => k.id === id); return x ? x.n : 'contacto'; };
  const reu = id => { const r = (S.datos && S.datos.reuniones || []).find(x => x.id === id); return r ? r.t : 'reunión'; };
  if (c.accion === 'EDITAR_CONTACTO') return 'Editar ' + nc(c.datos.cliente);
  if (c.accion === 'MARCAR_REUNION') return (c.datos.estado === 'CELEBRADA_CONFIRMADA' ? 'Realizada: ' : 'No se presentó: ') + reu(c.datos.reunion);
  if (c.accion === 'REPROGRAMAR_REUNION') return 'Reprogramar ' + reu(c.datos.reunion) + ' al ' + fmtHora(c.datos.inicio);
  if (c.accion === 'AGENDAR_REUNION') return 'Agendar con ' + nc(c.datos.cliente) + ' el ' + fmtHora(c.datos.inicio);
  if (c.accion === 'MOVER_ETAPA') return 'Mover a ' + c.datos.etapa + ': ' + (c.datos.nombre || 'oportunidad');
  if (c.accion === 'CREAR_OPORTUNIDAD') return 'Nueva oportunidad: ' + c.datos.nombre;
  if (c.accion === 'UNIFICAR') return 'Unificar ' + nc(c.datos.absorbido) + ' en ' + nc(c.datos.principal);
  if (c.accion === 'SON_DISTINTOS') return 'Marcar como personas distintas';
  return 'Nota: ' + String(c.datos.texto || '').slice(0, 60);
}
async function encolar(accion, datos, mensaje, deshacer) {
  const item = { id: 'CMB-' + uuid(), accion, datos, fecha: new Date().toISOString(), estado: 'pendiente' };
  S.cola.push(item); await guardarCola(); programarEnvio(); refrescar();
  avisar(mensaje, deshacer !== false ? async () => {
    const c = S.cola.find(x => x.id === item.id);
    if (!c || c.estado !== 'pendiente') { avisar('Ya se envió: no se puede deshacer'); return; }
    S.cola = S.cola.filter(x => x.id !== item.id); await guardarCola(); refrescar(); avisar('Cambio deshecho');
  } : null);
  return item;
}

/* ---------- Datos con los cambios aún no confirmados ---------- */
function tareas() {
  let l = (S.datos ? S.datos.tareas : []).map(t => Object.assign({}, t));
  S.cola.forEach(c => {
    if (c.accion === 'CERRAR_TAREA') l = l.filter(t => t.id !== c.datos.id);
    else if (c.accion === 'REPROGRAMAR_TAREA') { const t = l.find(x => x.id === c.datos.id); if (t) { t.v = c.datos.fecha; t.r = (t.r || 0) + 1; t.pend = 1; } }
    else if (c.accion === 'CREAR_TAREA' && !l.some(t => t.id === c.datos.id)) l.push({ id: c.datos.id, cli: c.datos.cliente || '', d: c.datos.descripcion, det: c.datos.detalle || '', v: c.datos.fecha || '', p: 'MEDIA', f: 'APP', pend: 1 });
  });
  return l;
}
/* Campos editables: nombre en el CRM → campo en el paquete. */
const MAPA_CAMPOS = { NOMBRE_COMPLETO: 'n', TELEFONO_PRINCIPAL: 'tp', WHATSAPP: 'w', CORREO_PRINCIPAL: 'cp', CIUDAD: 'ci', CARGO: 'cg', ESTADO_CLIENTE: 's', FECHA_NACIMIENTO: 'fn', NECESIDAD_PRINCIPAL: 'nec', OBJECIONES: 'obj', PROXIMA_ACCION: 'pa', FECHA_PROXIMO_CONTACTO: 'fp', NOTAS: 'not' };
const crudo = id => (S.datos ? S.datos.clientes : []).find(c => c.id === id);
/** Clientes con las ediciones y unificaciones aún no confirmadas ya aplicadas, para verlas al instante. */
function clientes() {
  if (!S.datos) return [];
  const edic = {}, fuera = {};
  S.cola.forEach(q => {
    if (q.accion === 'EDITAR_CONTACTO') edic[q.datos.cliente] = Object.assign(edic[q.datos.cliente] || {}, q.datos.campos);
    else if (q.accion === 'UNIFICAR') fuera[q.datos.absorbido] = q.datos.principal;
  });
  return S.datos.clientes.filter(c => !fuera[c.id]).map(c => {
    if (!edic[c.id]) return c;
    const x = Object.assign({}, c, { pend: 1 });
    Object.keys(edic[c.id]).forEach(k => { if (MAPA_CAMPOS[k]) x[MAPA_CAMPOS[k]] = edic[c.id][k]; });
    if (edic[c.id].TELEFONO_PRINCIPAL) x.tel = [edic[c.id].TELEFONO_PRINCIPAL].concat((c.tel || []).filter(t => t !== edic[c.id].TELEFONO_PRINCIPAL));
    if (edic[c.id].CORREO_PRINCIPAL) x.mail = [edic[c.id].CORREO_PRINCIPAL].concat((c.mail || []).filter(t => t !== edic[c.id].CORREO_PRINCIPAL));
    return x;
  });
}
const cliente = id => clientes().find(c => c.id === id);
const CERRADAS = ['Ganado', 'Perdido', 'Servicio finalizado'];
/** Oportunidades abiertas, con los movimientos y las creadas sin conexión. */
function oportunidades() {
  const l = [];
  (S.datos ? S.datos.clientes : []).forEach(c => (c.op || []).forEach(o => l.push(Object.assign({ cli: c.id }, o))));
  S.cola.forEach(q => {
    if (q.accion === 'MOVER_ETAPA') { const o = l.find(x => x.id === q.datos.opo); if (o) { o.e = q.datos.etapa; o.pend = 1; } }
    else if (q.accion === 'CREAR_OPORTUNIDAD' && !l.some(x => x.id === q.id)) l.push({ id: q.id, cli: q.datos.cliente, n: q.datos.nombre, e: q.datos.etapa, v: Number(q.datos.valor) || 0, m: 'COP', pend: 1, nueva: 1 });
  });
  return l;
}
/** Reuniones con lo marcado, reprogramado o agendado sin conexión. */
function reuniones() {
  const l = (S.datos ? S.datos.reuniones : []).map(r => Object.assign({}, r));
  S.cola.forEach(q => {
    if (q.accion === 'MARCAR_REUNION') { const r = l.find(x => x.id === q.datos.reunion); if (r) { r.e = q.datos.estado; r.pend = 1; } }
    else if (q.accion === 'REPROGRAMAR_REUNION') { const r = l.find(x => x.id === q.datos.reunion); if (r) { r.f = q.datos.inicio; r.e = 'PROGRAMADA'; r.pend = 1; } }
    else if (q.accion === 'AGENDAR_REUNION' && !l.some(x => x.id === q.id)) l.push({ id: q.id, cli: q.datos.cliente, t: q.datos.titulo || 'Reunión', f: q.datos.inicio, e: 'PROGRAMADA', u: q.datos.enlace || '', pend: 1, nueva: 1, meet: q.datos.meet });
  });
  return l;
}
const dinero = (v, m) => (m && m !== 'COP' ? m + ' ' : '$ ') + Math.round(Number(v) || 0).toString().replace(/\B(?=(\d{3})+(?!\d))/g, '.');
const nombreCli = id => { const c = cliente(id); return c ? c.n : ''; };
function ordenVence(a, b) { return (a.v || '9999').localeCompare(b.v || '9999'); }

/* ---------- Pintado ---------- */
const VISTAS = { dia: ['Mi día', vDia], tareas: ['Tareas', vTareas], clientes: ['Clientes', vClientes], embudo: ['Embudo', vEmbudo], sinc: ['Sincronizar', vSinc] };
function pintar() {
  const r = $('raiz'), ficha = S.vista === 'ficha', titulo = ficha ? (nombreCli(S.pila[S.pila.length - 1]) || 'Cliente') : VISTAS[S.vista][0];
  r.innerHTML = '<header class="cab">' + (ficha ? '<button class="volver" data-a="volver" aria-label="Volver">‹ Volver</button>' : '') + '<b>' + esc(titulo) + '</b><button class="estado" data-a="ir" data-v="sinc" id="est"></button></header><main id="m"></main><nav class="nav" aria-label="Secciones">' + ['dia', 'tareas', 'clientes', 'embudo', 'sinc'].map(v => '<button data-a="ir" data-v="' + v + '" class="' + (S.vista === v ? 'activo' : '') + '"' + (S.vista === v ? ' aria-current="page"' : '') + '>' + VISTAS[v][0] + '</button>').join('') + '</nav>';
  $('m').innerHTML = ficha ? vFicha(S.pila[S.pila.length - 1]) : VISTAS[S.vista][1]();
  pintarEstado();
}
function pintarEstado() {
  const e = $('est'); if (!e) return;
  const n = S.cola.length, cls = S.sincronizando ? '' : S.red === 'ok' && !n ? 'ok' : S.red === 'ok' ? '' : 'fuera';
  const txt = S.sincronizando ? 'Sincronizando' : S.red === 'revocado' ? 'Revocado' : n ? n + ' por confirmar' : S.red === 'fuera' ? 'Sin conexión' : 'Al día';
  e.innerHTML = '<span class="punto ' + cls + '"></span>' + esc(txt);
}
function refrescar() {
  if (!S.clave || !$('m')) { pintarEstado(); return; }
  const a = document.activeElement;
  if (a && /INPUT|TEXTAREA/.test(a.tagName)) { pintarEstado(); return; } // no interrumpe lo que se está escribiendo
  if (document.querySelector('.dialogo')) { pintarEstado(); return; }
  const y = window.scrollY; pintar(); window.scrollTo(0, y);
}
function tarjetaTarea(t) {
  const vencida = t.v && t.v < hoy(), cn = nombreCli(t.cli);
  return '<div class="card"><button class="tocable" data-a="verTarea" data-id="' + esc(t.id) + '"><h3>' + esc(t.d) + '</h3><span class="gris">' + esc(cn || 'Sin cliente') + '</span><br><span class="etq' + (vencida ? ' mal' : '') + '">' + (vencida ? 'Vencida ' : '') + fmtDia(t.v) + '</span>' + (t.pend ? '<span class="etq oro">Por confirmar</span>' : '') + '</button><div class="acc"><button class="b p" data-a="cerrarT" data-id="' + esc(t.id) + '">Cerrar</button><button class="b" data-a="reprog" data-id="' + esc(t.id) + '">Reprogramar</button>' + botonesContacto(cliente(t.cli)) + '</div></div>';
}
function tarjetaCumple(c, dias) {
  return '<div class="card"><button class="tocable" data-a="ficha" data-id="' + esc(c.id) + '"><h3>' + esc(c.n) + '</h3><span class="etq oro">' + (dias === 0 ? 'Cumple hoy' : dias === 1 ? 'Cumple mañana' : 'Cumple en ' + dias + ' días') + '</span></button><div class="acc">' + botonesContacto(c, dias === 0 ? 'CUMPLE_HOY' : 'CUMPLE_SEMANA') + '</div></div>';
}
function tarjetaInteres(c) {
  return '<div class="card"><button class="tocable" data-a="ficha" data-id="' + esc(c.id) + '"><h3>' + esc(c.n) + '</h3>' + etqInteres(c.pi) + '<br><span class="gris peq">' + esc(String(c.pm || '').split(' · ').slice(0, 3).join(' · ')) + '</span></button><div class="acc">' + botonesContacto(c) + '<button class="b" data-a="nuevaT" data-id="' + esc(c.id) + '">Nueva tarea</button></div></div>';
}
const ESTADO_REU = { PROGRAMADA: ['Programada', ''], PENDIENTE_CONFIRMAR: ['Por confirmar', 'oro'], CELEBRADA_CONFIRMADA: ['Realizada', ''], NO_CELEBRADA: ['No se presentó', 'mal'], CANCELADA: ['Cancelada', 'mal'] };
const nombreVideo = u => /meet\.google/.test(u) ? 'Google Meet' : /zoom\.us/.test(u) ? 'Zoom' : /teams\./.test(u) ? 'Teams' : 'la videollamada';
/** Una reunión con su enlace para unirse y lo que se puede hacer según su momento. */
function tarjetaReunion(r, sinNombre) {
  const u = enlace(r.u), cn = nombreCli(r.cli), t = new Date(r.f), pasada = !isNaN(t) && t.getTime() < Date.now() - 15 * 60000, proxima = !isNaN(t) && !pasada && t.getTime() - Date.now() < 30 * 60000;
  const st = ESTADO_REU[r.e] || [r.e || '', ''], porMarcar = pasada && (r.e === 'PROGRAMADA' || r.e === 'PENDIENTE_CONFIRMAR');
  let x = '<div class="card"><h3>' + esc(r.t || 'Reunión') + '</h3><span class="gris">' + esc(fmtHora(r.f)) + (cn && !sinNombre ? ' · ' + esc(cn) : '') + '</span>' + (st[0] ? ' <span class="etq ' + st[1] + '">' + st[0] + '</span>' : '') + (r.pend ? '<span class="etq oro">Por confirmar en el CRM</span>' : '');
  x += '<div class="acc">';
  if (u && !pasada) x += '<a class="b' + (proxima ? ' p' : '') + '" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">Unirse a ' + nombreVideo(u) + '</a>';
  else if (r.nueva && r.meet) x += '<span class="gris peq">El enlace de Meet llega al sincronizar</span>';
  if (porMarcar && !r.nueva) x += '<button class="b p" data-a="marcarR" data-id="' + esc(r.id) + '" data-e="CELEBRADA_CONFIRMADA">Realizada</button><button class="b" data-a="marcarR" data-id="' + esc(r.id) + '" data-e="NO_CELEBRADA">No se presentó</button>';
  if (!r.nueva && (r.e === 'PROGRAMADA' || r.e === 'PENDIENTE_CONFIRMAR' || r.e === 'NO_CELEBRADA')) x += '<button class="b" data-a="reprogR" data-id="' + esc(r.id) + '">Reprogramar</button>';
  if (r.cli && !pasada) x += '<button class="b" data-a="prep" data-id="' + esc(r.id) + '">Prepararme</button>';
  if (r.cli && !sinNombre) x += '<button class="b" data-a="ficha" data-id="' + esc(r.cli) + '">Ver cliente</button>';
  if (u && pasada) x += '<a class="b" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">Abrir enlace</a>';
  return x + '</div></div>';
}
function avisosHtml() {
  if (!S.avisos.length) return '';
  return '<button class="card tocable" data-a="ir" data-v="sinc"><span class="etq mal">Atención</span> ' + S.avisos.length + (S.avisos.length === 1 ? ' cambio no se aplicó como esperabas' : ' cambios no se aplicaron como esperabas') + '</button>';
}
function vDia() {
  if (!S.datos) return '<div class="vacio">Aún no hay datos. Sincroniza con internet para descargarlos.</div>';
  const h = hoy(), ts = tareas(), venc = ts.filter(t => t.v && t.v < h).sort(ordenVence), deHoy = ts.filter(t => t.v === h);
  const todasR = reuniones(), rs = todasR.filter(r => { const d = new Date(r.f); return !isNaN(d) && d >= new Date(new Date().setHours(0, 0, 0, 0)) && r.e !== 'CANCELADA'; }).sort((a, b) => new Date(a.f) - new Date(b.f));
  // Reuniones de los últimos 14 días que pasaron sin marcar si se hicieron.
  const porConfirmar = todasR.filter(r => { const d = new Date(r.f); return r.cli && !isNaN(d) && d.getTime() < Date.now() - 15 * 60000 && d.getTime() > Date.now() - 14 * 86400000 && (r.e === 'PROGRAMADA' || r.e === 'PENDIENTE_CONFIRMAR'); }).sort((a, b) => new Date(b.f) - new Date(a.f));
  const rHoy = rs.filter(r => fechaLocal(new Date(r.f)) === h), rProx = rs.filter(r => fechaLocal(new Date(r.f)) !== h && fechaLocal(new Date(r.f)) <= masDias(7));
  let x = '<h1>' + esc(new Date().toLocaleDateString('es-CO', { weekday: 'long', day: 'numeric', month: 'long' })) + '</h1>' + avisosHtml();
  x += '<div class="met"><button class="' + (venc.length ? 'malo' : '') + '" data-a="filtrar" data-f="vencidas"><strong>' + venc.length + '</strong><span>Vencidas</span></button><button data-a="filtrar" data-f="hoy"><strong>' + deHoy.length + '</strong><span>Para hoy</span></button><button data-a="filtrar" data-f="todas"><strong>' + ts.length + '</strong><span>Abiertas</span></button></div>';
  const cumples = clientes().map(c => ({ c, d: diasCumple(c.cu) })).filter(x => x.d !== null && x.d <= 7).sort((a, b) => a.d - b.d || a.c.n.localeCompare(b.c.n, 'es'));
  const cHoy = cumples.filter(x => x.d === 0), cProx = cumples.filter(x => x.d > 0);
  if (cHoy.length) x += '<h2>Cumpleaños de hoy</h2>' + cHoy.map(x2 => tarjetaCumple(x2.c, 0)).join('');
  x += '<h2>Reuniones de hoy</h2>' + (rHoy.length ? rHoy.map(r => tarjetaReunion(r)).join('') : '<p class="gris">Ninguna reunión hoy.</p>');
  if (porConfirmar.length) x += '<h2>¿Se hicieron estas reuniones?</h2>' + porConfirmar.slice(0, 10).map(r => tarjetaReunion(r)).join('');
  x += '<h2>Tareas de hoy</h2>' + (deHoy.length ? deHoy.map(tarjetaTarea).join('') : '<p class="gris">Nada programado para hoy.</p>');
  if (venc.length) x += '<h2>Vencidas</h2>' + venc.slice(0, 30).map(tarjetaTarea).join('') + (venc.length > 30 ? '<button class="b ancho" data-a="filtrar" data-f="vencidas">Ver las ' + venc.length + '</button>' : '');
  // Los más interesados sin ninguna tarea abierta: nadie los está atendiendo.
  const conTarea = {}; ts.forEach(t => { if (t.cli) conTarea[t.cli] = 1; });
  const intere = clientes().filter(c => (c.pi || 0) >= 50 && !conTarea[c.id] && c.s !== 'ACTIVO' && c.s !== 'PERDIDO').sort((a, b) => b.pi - a.pi).slice(0, 5);
  if (intere.length) x += '<h2>Interesados sin seguimiento</h2>' + intere.map(tarjetaInteres).join('');
  if (rProx.length) x += '<h2>Próximos 7 días</h2>' + rProx.map(r => tarjetaReunion(r)).join('');
  if (cProx.length) x += '<h2>Cumpleaños de la semana</h2>' + cProx.map(x2 => tarjetaCumple(x2.c, x2.d)).join('');
  return x;
}
const FILTROS = [['todas', 'Todas'], ['vencidas', 'Vencidas'], ['hoy', 'Hoy'], ['prox', 'Próximas'], ['sinf', 'Sin fecha'], ['sinc', 'Sin cliente']];
function vTareas() {
  const h = hoy(), f = S.filtro, l = tareas().filter(t => f === 'todas' || (f === 'vencidas' && t.v && t.v < h) || (f === 'hoy' && t.v === h) || (f === 'prox' && t.v > h) || (f === 'sinf' && !t.v) || (f === 'sinc' && !t.cli)).sort(ordenVence);
  return '<button class="b p ancho" data-a="nuevaT">Nueva tarea</button><div class="chips">' + '' + FILTROS.map(x => '<button data-a="filtrar" data-f="' + x[0] + '" class="' + (f === x[0] ? 'activo' : '') + '">' + x[1] + '</button>').join('') + '</div><p class="gris">' + l.length + (l.length === 1 ? ' tarea' : ' tareas') + '</p>' + (l.length ? l.slice(0, 200).map(tarjetaTarea).join('') : '<div class="vacio">No hay tareas en este filtro.</div>');
}
function buscarCli(q, tope) {
  const n = norm(q).trim(), dig = n.replace(/\D/g, '');
  const l = clientes().filter(c => !n || norm(c.n).includes(n) || (c.mail || []).some(m => m.includes(n)) || (dig.length >= 4 && (c.tel || []).some(t => t.replace(/\D/g, '').includes(dig))));
  return { total: l.length, lista: l.sort((a, b) => a.n.localeCompare(b.n, 'es')).slice(0, tope) };
}
function listaCli() {
  const r = buscarCli(S.busqueda, 60);
  return '<p class="gris">' + r.total + (r.total === 1 ? ' cliente' : ' clientes') + (r.total > 60 ? '; escribe para acotar' : '') + '</p>' + (r.lista.length ? r.lista.map(c => '<button class="card tocable" data-a="ficha" data-id="' + esc(c.id) + '"><h3>' + esc(c.n) + '</h3><span class="gris">' + esc((c.tel && c.tel[0]) || (c.mail && c.mail[0]) || 'Sin datos de contacto') + (c.ci ? ' · ' + esc(c.ci) : '') + '</span></button>').join('') : '<div class="vacio">Sin coincidencias.</div>');
}
/** Pares que el CRM cree que son la misma persona y que siguen en los datos, sin los ya decididos aquí. */
function repetidos() {
  const hechos = {}; S.cola.forEach(q => { if (q.accion === 'UNIFICAR' || q.accion === 'SON_DISTINTOS') { const a = q.datos.a || q.datos.principal, b = q.datos.b || q.datos.absorbido; hechos[[a, b].sort().join('|')] = 1; } });
  return ((S.datos && S.datos.dup) || []).filter(p => cliente(p.a) && cliente(p.b) && !hechos[[p.a, p.b].sort().join('|')]);
}
function vClientes() {
  const rep = repetidos().length;
  return '<div class="acc"><button class="b" data-a="tarjeta">Escanear tarjeta</button>' + (rep ? '<button class="b" data-a="verRep">Posibles repetidos (' + rep + ')</button>' : '') + '</div><label for="q">Buscar por nombre, teléfono o correo</label><input id="q" type="search" autocomplete="off" autocapitalize="off" value="' + esc(S.busqueda) + '" data-e="buscar"><div id="lc">' + listaCli() + '</div>';
}
function vFicha(id) {
  const c = cliente(id); if (!c) return '<div class="vacio">Este cliente ya no está en los datos descargados.</div>';
  const ts = tareas().filter(t => t.cli === id).sort(ordenVence), rs = reuniones().filter(r => r.cli === id).sort((a, b) => new Date(b.f) - new Date(a.f)), ops = oportunidades().filter(o => o.cli === id);
  const notas = S.cola.filter(n => n.accion === 'AGREGAR_NOTA' && n.datos.cliente === id).map(n => ({ f: n.fecha.slice(0, 10), c: 'APP', a: 'Nota', r: n.datos.texto, pend: 1 })), his = notas.concat(c.his || []);
  const dc = diasCumple(c.cu), car = enlace(c.car);
  let x = '<h1>' + esc(c.n) + '</h1><span class="etq">' + esc(String(c.s || '').replace(/_/g, ' ')) + '</span>' + (c.ci ? '<span class="etq">' + esc(c.ci) + '</span>' : '') + etqInteres(c.pi) + (dc === 0 ? '<span class="etq oro">Cumple hoy</span>' : '') + String(c.et || '').split('|').map(t => t.trim()).filter(Boolean).map(t => '<span class="etq"># ' + esc(t) + '</span>').join('');
  x += '<div class="acc">' + botonesContacto(c, dc === 0 ? 'CUMPLE_HOY' : dc !== null && dc <= 7 ? 'CUMPLE_SEMANA' : '') + (car ? '<a class="b" target="_blank" rel="noopener noreferrer" href="' + esc(car) + '">Carpeta</a>' : '') + '</div>';
  x += '<div class="acc"><button class="b p" data-a="agendar" data-id="' + esc(id) + '">Agendar reunión</button><button class="b" data-a="nuevaT" data-id="' + esc(id) + '">Nueva tarea</button><button class="b" data-a="nota" data-id="' + esc(id) + '">Agregar nota</button></div>';
  x += '<div class="acc"><button class="b" data-a="editar" data-id="' + esc(id) + '">Editar contacto</button><button class="b" data-a="foto" data-id="' + esc(id) + '">Foto de documento</button><button class="b" data-a="unificar" data-id="' + esc(id) + '">Unificar con otro</button></div>' + (c.pend ? '<p class="gris peq">Tiene cambios por confirmar en el CRM.</p>' : '');
  const cumpleTxt = c.cu ? new Date('2000-' + c.cu + 'T12:00:00').toLocaleDateString('es-CO', { day: 'numeric', month: 'long' }) + (dc === 0 ? ' (hoy)' : dc !== null ? ' (en ' + dc + (dc === 1 ? ' día)' : ' días)') : '') : '';
  const datos = [['Teléfonos', (c.tel || []).join(', ')], ['Correos', (c.mail || []).join(', ')], ['Cumpleaños', cumpleTxt], ['Relación', c.rc], ['Llegó por', c.fu], ['Interés', c.pi ? c.pi + '/100 · ' + (c.pm || '') : ''], ['Necesidad', c.nec], ['Objeciones', c.obj], ['Próxima acción', c.pa], ['Próximo contacto', c.fp ? fmtDia(c.fp) : ''], ['Notas', c.not]].filter(d => d[1]);
  if (datos.length) x += '<h2>Datos</h2><div class="card">' + datos.map(d => '<p><b>' + d[0] + '</b><br><span class="texto">' + esc(d[1]) + '</span></p>').join('') + '</div>';
  if (c.pp || c.pf) x += '<h2>Perfil</h2><div class="card">' + (c.pp ? '<p><b>Pensional</b><br><span class="texto">' + esc(c.pp) + '</span></p>' : '') + (c.pf ? '<p><b>Financiero</b><br><span class="texto">' + esc(c.pf) + '</span></p>' : '') + '</div>';
  if ((c.doc || []).length || c.ce) x += '<h2>Expediente</h2><div class="card">' + (c.ce ? '<p class="gris">' + (c.ce === 'VERIFICADA' ? 'Carpeta vinculada' : 'Carpeta con ruta histórica sin verificar') + '</p>' : '') + (c.doc || []).map(d => { const u = enlace(d.u); return '<div class="fila"><span>' + (u ? '<a target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">' + esc(d.n || 'Documento') + '</a>' : esc(d.n || 'Documento')) + (d.t ? ' <span class="gris peq">' + esc(String(d.t).replace(/_/g, ' ').toLowerCase()) + '</span>' : '') + '</span><span class="gris peq">' + (d.f ? fmtDia(d.f) : '') + '</span></div>'; }).join('') + '</div>';
  const futuras = rs.filter(r => new Date(r.f).getTime() >= Date.now() - 15 * 60000 && r.e !== 'CANCELADA').reverse(), porMarcar = rs.filter(r => new Date(r.f).getTime() < Date.now() - 15 * 60000 && (r.e === 'PROGRAMADA' || r.e === 'PENDIENTE_CONFIRMAR'));
  if (futuras.length || porMarcar.length) x += '<h2>Reuniones</h2>' + futuras.map(r => tarjetaReunion(r, 1)).join('') + porMarcar.map(r => tarjetaReunion(r, 1)).join('');
  x += '<h2>Oportunidades</h2>' + ops.map(tarjetaOportunidad).join('') + '<button class="b ancho" data-a="nuevaO" data-id="' + esc(id) + '">+ Oportunidad</button>';
  if ((c.df || []).length) x += '<h2>Documentos que faltan</h2><div class="card">' + c.df.map(t => '<span class="etq mal">' + esc(String(t).replace(/_/g, ' ').toLowerCase()) + '</span>').join('') + '</div>';
  x += '<h2>Tareas abiertas</h2>' + (ts.length ? ts.map(tarjetaTarea).join('') : '<p class="gris">Sin tareas abiertas.</p>');
  if ((c.com || []).length) x += '<h2>Compromisos</h2><div class="card">' + c.com.map(k => '<div class="fila"><span>' + esc(k.d) + '</span><span class="gris peq">' + fmtDia(k.f) + '</span></div>').join('') + '</div>';
  if ((c.res || []).length) x += '<h2>Resúmenes de reuniones</h2><div class="card">' + c.res.map(r => { const u = enlace(r.u); return '<details><summary>' + esc(r.t) + ' · ' + fmtDia(r.f) + '</summary><p class="texto">' + esc(r.ej) + '</p>' + (r.n ? '<p><b>Necesidades</b><br>' + esc(r.n) + '</p>' : '') + (r.o ? '<p><b>Objeciones</b><br>' + esc(r.o) + '</p>' : '') + (r.p ? '<p><b>Próximos pasos</b><br>' + esc(r.p) + '</p>' : '') + (u ? '<a class="b" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">Ver grabación</a>' : '') + '</details>'; }).join('') + '</div>';
  const pasadas = rs.filter(r => futuras.indexOf(r) < 0 && porMarcar.indexOf(r) < 0);
  if (pasadas.length) x += '<h2>Reuniones anteriores</h2><div class="card">' + pasadas.slice(0, 15).map(r => '<div class="fila"><span>' + esc(r.t) + ' <span class="gris peq">' + esc((ESTADO_REU[r.e] || [''])[0]) + '</span></span><span class="gris peq">' + esc(fmtHora(r.f)) + '</span></div>').join('') + '</div>';
  if (his.length) x += '<h2>Historial reciente</h2><div class="card">' + his.map(h => '<details><summary>' + fmtDia(h.f) + ' · ' + esc(h.c) + (h.pend ? ' · por confirmar' : '') + (h.q ? ' · espera respuesta' : '') + '</summary><p class="texto">' + esc(h.r || h.a) + '</p></details>').join('') + '</div>';
  return x;
}
function vSinc() {
  const gen = S.datos && S.datos.generado, env = S.cola.filter(c => c.estado === 'enviado').length, pen = S.cola.length - env;
  let x = '<div class="card"><p><b>' + (S.sincronizando ? 'Comprobando conexión…' : S.red === 'revocado' ? 'Este dispositivo fue revocado. Vuelve a vincularlo desde el CRM' : S.red === 'fuera' ? 'Sin conexión con el CRM' : 'Conectado') + '</b></p><p class="gris">Datos del CRM: ' + (gen ? esc(fmtHora(gen)) : 'sin descargar') + '<br>Última sincronización: ' + (S.ultima ? esc(fmtHora(S.ultima)) : 'nunca') + '</p><p class="gris">' + pen + ' por enviar · ' + env + ' enviados, esperando que el CRM los aplique (hasta 10 minutos)</p><button class="b p ancho" data-a="sync"' + (S.sincronizando || S.revocado ? ' disabled' : '') + '>' + (S.sincronizando ? 'Sincronizando…' : 'Sincronizar ahora') + '</button></div>';
  if (S.avisos.length) x += '<h2>Requieren tu atención</h2>' + S.avisos.map(a => '<div class="card"><span class="etq mal">' + (a.tipo === 'CONFLICTO' ? 'Conflicto' : 'No aplicado') + '</span><p>' + esc(a.texto) + '</p><p class="gris">' + esc(a.motivo) + (a.tipo === 'CONFLICTO' ? '. Quedó en Revisión del CRM.' : '') + '</p><button class="b" data-a="quitarAviso" data-id="' + esc(a.id) + '">Entendido</button></div>').join('');
  if (S.cola.length) x += '<h2>Cambios por confirmar</h2><div class="card">' + S.cola.map(c => '<div class="fila"><span>' + esc(describir(c)) + '</span><span class="gris peq">' + (c.estado === 'enviado' ? 'Enviado' : 'Por enviar') + '</span></div>').join('') + '</div>';
  if (S.bioPuede) x += '<h2>Face ID</h2><div class="card"><p class="gris">' + (S.bioActivo ? 'Activado: en la pantalla del PIN toca "Entrar con Face ID".' : 'Desbloquea la app con tu cara en vez de escribir el PIN.') + '</p><button class="b' + (S.bioActivo ? '' : ' p') + '" data-a="' + (S.bioActivo ? 'bioOff' : 'bioOn') + '">' + (S.bioActivo ? 'Desactivar Face ID' : 'Activar Face ID') + '</button></div>';
  x += '<h2>Este dispositivo</h2><div class="card"><p class="gris">' + esc(S.sesion && S.sesion.nombre || '') + ' · Versión de la app ' + VERSION_APP + '</p><div class="acc"><button class="b" data-a="bloquear">Bloquear ahora</button><button class="b mal" data-a="desvincular">Borrar datos de este dispositivo</button></div></div>';
  return x;
}

/* ---------- Embudo ---------- */
function tarjetaOportunidad(o) {
  const cerr = CERRADAS.indexOf(o.e) >= 0;
  return '<div class="card"><button class="tocable" data-a="ficha" data-id="' + esc(o.cli) + '"><h3>' + esc(o.n) + '</h3><span class="gris">' + esc(nombreCli(o.cli)) + (o.v ? ' · ' + dinero(o.v, o.m) : '') + '</span><br><span class="etq' + (o.e === 'Ganado' ? ' oro' : o.e === 'Perdido' ? ' mal' : '') + '">' + esc(o.e) + '</span>' + (o.pend ? '<span class="etq oro">Por confirmar</span>' : '') + '</button>' + (o.nueva || cerr ? '' : '<div class="acc"><button class="b" data-a="moverO" data-id="' + esc(o.id) + '">Mover de etapa</button><button class="b p" data-a="moverYa" data-id="' + esc(o.id) + '" data-e="' + esc(siguienteEtapa(o.e)) + '">' + esc(siguienteEtapa(o.e)) + ' ›</button></div>') + '</div>';
}
function etapasAbiertas() { return ((S.datos && S.datos.etapas) || []).filter(e => CERRADAS.indexOf(e) < 0 && ['Cliente activo', 'Fidelización', 'Reactivación'].indexOf(e) < 0); }
function siguienteEtapa(e) { const l = etapasAbiertas(), i = l.indexOf(e); return i >= 0 && i < l.length - 1 ? l[i + 1] : 'Ganado'; }
function vEmbudo() {
  if (!S.datos) return '<div class="vacio">Aún no hay datos. Sincroniza con internet para descargarlos.</div>';
  const ops = oportunidades(), et = etapasAbiertas(), abiertas = ops.filter(o => CERRADAS.indexOf(o.e) < 0);
  const tot = abiertas.reduce((s, o) => s + (o.m === 'COP' || !o.m ? o.v || 0 : 0), 0), f = S.etapa || '';
  let x = '<div class="met"><button><strong>' + abiertas.length + '</strong><span>Abiertas</span></button><button><strong style="font-size:15px">' + dinero(tot) + '</strong><span>Valor en COP</span></button></div>';
  x += '<button class="b p ancho" data-a="nuevaO">+ Oportunidad</button><div class="chips"><button data-a="verEtapa" data-e="" class="' + (!f ? 'activo' : '') + '">Todas</button>' + et.map(e => { const n = abiertas.filter(o => o.e === e).length; return n ? '<button data-a="verEtapa" data-e="' + esc(e) + '" class="' + (f === e ? 'activo' : '') + '">' + esc(e) + ' (' + n + ')</button>' : ''; }).join('') + '</div>';
  const grupos = (f ? [f] : et).map(e => [e, abiertas.filter(o => o.e === e)]).filter(g => g[1].length);
  x += grupos.length ? grupos.map(g => '<h2>' + esc(g[0]) + ' <span class="gris peq">' + g[1].length + ' · ' + dinero(g[1].reduce((s, o) => s + (o.v || 0), 0)) + '</span></h2>' + g[1].map(tarjetaOportunidad).join('')).join('') : '<div class="vacio">No hay oportunidades abiertas' + (f ? ' en esta etapa' : '') + '.</div>';
  const movidas = ops.filter(o => o.pend && CERRADAS.indexOf(o.e) >= 0);
  if (movidas.length) x += '<h2>Cerradas hace poco</h2>' + movidas.map(tarjetaOportunidad).join('');
  return x;
}

/* ---------- Fotos de documentos y tarjetas ---------- */
function comprimir(f) {
  return new Promise((ok, mal) => {
    const u = URL.createObjectURL(f), im = new Image();
    im.onload = () => { const k = Math.min(1, 2000 / Math.max(im.width, im.height)), cv = document.createElement('canvas'); cv.width = Math.round(im.width * k); cv.height = Math.round(im.height * k); cv.getContext('2d').drawImage(im, 0, 0, cv.width, cv.height); URL.revokeObjectURL(u); ok({ mime: 'image/jpeg', b64: cv.toDataURL('image/jpeg', 0.82).split(',')[1] }); };
    im.onerror = () => { URL.revokeObjectURL(u); mal(new Error('No se pudo leer la imagen')); };
    im.src = u;
  });
}
const aBase64 = f => new Promise((ok, mal) => { const r = new FileReader(); r.onload = () => ok(String(r.result).split(',')[1]); r.onerror = () => mal(r.error); r.readAsDataURL(f); });
/** Sube de inmediato: las fotos no se guardan en el celular. Requiere internet. */
async function subirArchivo(f, tipo, cli, nombre) {
  if (!f) { avisar('Elige una foto o un PDF'); return false; }
  if (navigator.onLine === false) { avisar('Subir fotos requiere internet'); return false; }
  try {
    let mime = f.type, b64;
    if (/^image\//.test(mime)) ({ mime, b64 } = await comprimir(f));
    else if (mime === 'application/pdf') { if (f.size > 4.5e6) { avisar('El PDF supera 4,5 MB'); return false; } b64 = await aBase64(f); }
    else { avisar('Solo fotos o PDF'); return false; }
    avisar('Subiendo…');
    const r = await llamar({ accion: 'archivo', token: S.sesion.token, id: 'CMB-' + uuid(), tipo, cliente: cli || '', nombre: nombre || '', mime, datos: b64, fecha: new Date().toISOString() });
    if (r.error === 'NO_AUTORIZADO') { S.revocado = true; throw new Error('Este dispositivo fue revocado'); }
    if (!r.ok) throw new Error(r.error === 'ARCHIVO_GRANDE' ? 'El archivo es muy grande' : 'El CRM no lo aceptó');
    avisar(tipo === 'TARJETA' ? 'Tarjeta enviada: la verás en Revisión del CRM en unos minutos' : 'Documento enviado a su expediente');
    return true;
  } catch (e) { avisar('No se pudo subir: ' + (e.name === 'TypeError' || e.name === 'AbortError' ? 'sin conexión' : e.message)); return false; }
}

/* ---------- Face ID (WebAuthn con PRF) ----------
 * El PIN se guarda cifrado con un secreto que el iPhone solo entrega tras Face ID. Sin ese secreto
 * no se puede leer, y el PIN sigue sirviendo siempre. Requiere iOS 18 o posterior.
 */
async function bioDisponible() { try { return !!(window.PublicKeyCredential && PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()); } catch (e) { return false; } }
async function claveBio(credId, sal) {
  const a = await navigator.credentials.get({ publicKey: { challenge: crypto.getRandomValues(new Uint8Array(32)), allowCredentials: [{ type: 'public-key', id: credId }], userVerification: 'required', timeout: 60000, extensions: { prf: { eval: { first: sal } } } } });
  const r = a.getClientExtensionResults(), s = r && r.prf && r.prf.results && r.prf.results.first;
  if (!s) throw new Error('SIN_PRF');
  return crypto.subtle.importKey('raw', s, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
async function activarBio(pin) {
  const sal = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({ publicKey: { rp: { name: 'OI CRM' }, user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'oi-crm', displayName: 'OI CRM' }, challenge: crypto.getRandomValues(new Uint8Array(32)), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }], authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'preferred' }, timeout: 60000, extensions: { prf: {} } } });
  const ext = cred.getClientExtensionResults(); if (ext && ext.prf && ext.prf.enabled === false) throw new Error('SIN_PRF');
  const id = new Uint8Array(cred.rawId), k = await claveBio(id, sal), iv = crypto.getRandomValues(new Uint8Array(12));
  const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, new TextEncoder().encode(pin));
  await kvPoner('bio', { id, sal, iv, c });
}
async function entrarBio() {
  const b = await kvLeer('bio'); if (!b) return;
  try { const k = await claveBio(b.id, b.sal); $('pp').value = new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b.iv }, k, b.c)); entrar(); }
  catch (e) { $('perr').textContent = 'No se pudo usar Face ID. Escribe tu PIN.'; }
}

/* ---------- Diálogos ---------- */
function dialogo(html) { cerrarDialogo(); const d = document.createElement('div'); d.className = 'dialogo'; d.setAttribute('role', 'dialog'); d.setAttribute('aria-modal', 'true'); d.innerHTML = '<div class="caja">' + html + '</div>'; document.body.appendChild(d); }
function cerrarDialogo() { const d = document.querySelector('.dialogo'); if (d) d.remove(); }
let tAviso = null, accionAviso = null;
function avisar(msg, deshacer) {
  const a = $('aviso'); accionAviso = deshacer || null;
  a.innerHTML = '<span>' + esc(msg) + '</span>' + (deshacer ? '<button data-a="deshacer">Deshacer</button>' : ''); a.hidden = false;
  clearTimeout(tAviso); tAviso = setTimeout(() => { a.hidden = true; accionAviso = null; }, deshacer ? ESPERA_ENVIO_MS - 500 : 3500);
}
const A = {
  ir(el) { S.vista = el.dataset.v; S.pila = []; pintar(); window.scrollTo(0, 0); },
  filtrar(el) { S.filtro = el.dataset.f; S.vista = 'tareas'; pintar(); window.scrollTo(0, 0); },
  ficha(el) { cerrarDialogo(); if (S.vista !== 'ficha') S.vistaPrevia = S.vista; S.pila.push(el.dataset.id); S.vista = 'ficha'; pintar(); window.scrollTo(0, 0); },
  volver() { S.pila.pop(); S.vista = S.pila.length ? 'ficha' : (S.vistaPrevia || 'clientes'); pintar(); },
  sync() { sincronizar(); },
  deshacer() { const f = accionAviso; $('aviso').hidden = true; accionAviso = null; if (f) f(); },
  cerrarD() { cerrarDialogo(); },
  cerrarT(el) { cerrarDialogo(); encolar('CERRAR_TAREA', { id: el.dataset.id }, 'Tarea cerrada'); },
  reprog(el) {
    const t = tareas().find(x => x.id === el.dataset.id); if (!t) return;
    dialogo('<h3>Reprogramar</h3><p class="gris">' + esc(t.d) + '</p><div class="acc"><button class="b" data-a="reprogYa" data-id="' + esc(t.id) + '" data-f="' + masDias(1) + '">Mañana</button><button class="b" data-a="reprogYa" data-id="' + esc(t.id) + '" data-f="' + masDias(7) + '">En 7 días</button></div><label for="rf">Otra fecha</label><input id="rf" type="date" min="' + hoy() + '" value="' + esc(t.v && t.v >= hoy() ? t.v : '') + '"><div id="rerr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="reprogYa" data-id="' + esc(t.id) + '">Guardar fecha</button></div>');
  },
  reprogYa(el) {
    const f = el.dataset.f || $('rf').value; if (!f) { $('rerr').textContent = 'Elige una fecha.'; return; }
    const orig = (S.datos.tareas || []).find(x => x.id === el.dataset.id), previo = [...S.cola].reverse().find(c => c.accion === 'REPROGRAMAR_TAREA' && c.datos.id === el.dataset.id);
    cerrarDialogo();
    encolar('REPROGRAMAR_TAREA', { id: el.dataset.id, fecha: f, base: previo ? previo.datos.fecha : (orig ? orig.v : '') }, 'Reprogramada para ' + fmtDia(f));
  },
  verTarea(el) {
    const t = tareas().find(x => x.id === el.dataset.id); if (!t) return;
    const u = enlace(t.e), cn = nombreCli(t.cli);
    dialogo('<h3>' + esc(t.d) + '</h3><p class="gris">' + esc(cn || 'Sin cliente') + ' · ' + fmtDia(t.v) + (t.f ? ' · ' + esc(t.f) : '') + (t.r ? ' · reprogramada ' + t.r + (t.r === 1 ? ' vez' : ' veces') : '') + '</p>' + (t.det ? '<p class="texto">' + esc(t.det) + '</p>' : '') + '<div class="acc"><button class="b p" data-a="cerrarT" data-id="' + esc(t.id) + '">Cerrar tarea</button><button class="b" data-a="reprog" data-id="' + esc(t.id) + '">Reprogramar</button>' + (t.cli ? '<button class="b" data-a="ficha" data-id="' + esc(t.cli) + '">Ver cliente</button>' : '') + (u ? '<a class="b" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">Abrir origen</a>' : '') + '<button class="b" data-a="cerrarD">Volver</button></div>');
  },
  nuevaT(el) {
    const id = el.dataset.id || '';
    dialogo('<h3>Nueva tarea</h3><label for="nd">Qué hay que hacer</label><textarea id="nd" rows="3" maxlength="500"></textarea><label for="nf">Fecha (opcional)</label><input id="nf" type="date">' + (id ? '<p class="gris">Cliente: ' + esc(nombreCli(id)) + '</p><input type="hidden" id="nc" value="' + esc(id) + '">' : '<label for="nq">Cliente (opcional)</label><input id="nq" type="search" autocomplete="off" data-e="buscarNT"><input type="hidden" id="nc"><div id="ns"></div>') + '<div id="nerr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="crearT">Guardar tarea</button></div>');
    $('nd').focus();
  },
  elegirC(el) { $('nc').value = el.dataset.id; $('nq').value = el.textContent; $('ns').innerHTML = ''; },
  crearT() {
    const d = $('nd').value.trim(); if (!d) { $('nerr').textContent = 'Escribe la tarea.'; return; }
    const datos = { id: 'APP-' + uuid(), descripcion: d, fecha: $('nf').value, cliente: $('nc').value };
    cerrarDialogo(); encolar('CREAR_TAREA', datos, 'Tarea creada');
  },
  wa(el) {
    const c = cliente(el.dataset.id); if (!c) return;
    const dig = digitosWa(c), ctx = el.dataset.ctx || '', pl = (S.datos.plantillas || []).slice();
    // Las del momento (por ejemplo, cumpleaños) van primero.
    pl.sort((a, b) => (b.s === ctx) - (a.s === ctx) || a.n.localeCompare(b.n, 'es'));
    const op = (t, txt) => '<a class="card tocable" style="display:block;text-decoration:none;color:inherit" target="_blank" rel="noopener noreferrer" href="' + esc(urlWa(dig, txt)) + '"><b>' + esc(t) + '</b>' + (txt ? '<br><span class="gris peq">' + esc(txt.slice(0, 140)) + (txt.length > 140 ? '…' : '') + '</span>' : '') + '</a>';
    dialogo('<h3>WhatsApp a ' + esc(c.n) + '</h3><p class="gris peq">Se abre WhatsApp con el texto escrito. Revísalo y envíalo tú.</p><div style="max-height:60vh;overflow:auto">' + op('Mensaje en blanco', '') + pl.map(p => op(p.n, rellenar(p.m, c))).join('') + '</div><div class="acc"><button class="b" data-a="cerrarD">Cerrar</button></div>');
  },
  // ----- Reuniones -----
  marcarR(el) { cerrarDialogo(); encolar('MARCAR_REUNION', { reunion: el.dataset.id, estado: el.dataset.e }, el.dataset.e === 'CELEBRADA_CONFIRMADA' ? 'Marcada como realizada' : 'Marcada: no se presentó'); },
  reprogR(el) {
    const r = reuniones().find(x => x.id === el.dataset.id); if (!r) return;
    if (r.fc) { dialogo('<h3>Cita de Funnelcenter</h3><p>Esta cita se agendó en Funnelcenter. Reprográmala allí para que el cliente reciba el aviso; el CRM la actualizará solo.</p><div class="acc"><button class="b p" data-a="cerrarD">Entendido</button></div>'); return; }
    const d = new Date(r.f), dia = isNaN(d) ? hoy() : fechaLocal(d), hora = isNaN(d) ? '09:00' : dos(d.getHours()) + ':' + dos(d.getMinutes());
    dialogo('<h3>Reprogramar reunión</h3><p class="gris">' + esc(r.t) + '</p><label for="rrf">Nuevo día</label><input id="rrf" type="date" min="' + hoy() + '" value="' + esc(dia >= hoy() ? dia : '') + '"><label for="rrh">Hora</label><input id="rrh" type="time" value="' + esc(hora) + '"><p class="gris peq">Se mueve también en tu Google Calendar. Avísale al cliente del cambio.</p><div id="rrerr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="reprogRYa" data-id="' + esc(r.id) + '">Guardar</button></div>');
  },
  reprogRYa(el) {
    const f = $('rrf').value, h = $('rrh').value; if (!f || !h) { $('rrerr').textContent = 'Elige día y hora.'; return; }
    const r = (S.datos.reuniones || []).find(x => x.id === el.dataset.id), ini = new Date(f + 'T' + h + ':00');
    cerrarDialogo(); encolar('REPROGRAMAR_REUNION', { reunion: el.dataset.id, inicio: ini.toISOString(), base: r ? r.f : '' }, 'Reprogramada para ' + fmtHora(ini.toISOString()));
  },
  agendar(el) {
    const c = cliente(el.dataset.id); if (!c) return; const mail = (c.mail || [])[0] || '';
    dialogo('<h3>Agendar con ' + esc(c.n) + '</h3><label for="agt">Título</label><input id="agt" value="' + esc('Asesoría con ' + c.n) + '" maxlength="150"><label for="agf">Día</label><input id="agf" type="date" min="' + hoy() + '" value="' + masDias(1) + '"><label for="agh">Hora</label><input id="agh" type="time" value="09:00"><label for="agd">Duración</label><select id="agd"><option value="30">30 minutos</option><option value="45">45 minutos</option><option value="60" selected>1 hora</option><option value="90">1 hora y media</option></select><label class="fila"><span>Crear videollamada de Google Meet</span><input id="agm" type="checkbox" checked style="width:auto"></label>' + (mail ? '<label class="fila"><span>Enviar la invitación a ' + esc(mail) + '</span><input id="agi" type="checkbox" style="width:auto"></label>' : '<p class="gris peq">No tiene correo: la reunión queda solo en tu calendario.</p>') + '<label for="agl">O un lugar o enlace propio (opcional)</label><input id="agl" placeholder="Oficina, dirección o enlace de Zoom"><div id="agerr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="agendarYa" data-id="' + esc(c.id) + '">Agendar</button></div>');
  },
  agendarYa(el) {
    const f = $('agf').value, h = $('agh').value; if (!f || !h) { $('agerr').textContent = 'Elige día y hora.'; return; }
    const ini = new Date(f + 'T' + h + ':00'); if (ini.getTime() < Date.now() - 60000) { $('agerr').textContent = 'Esa hora ya pasó.'; return; }
    const lugar = $('agl').value.trim(), esEnlace = /^https?:\/\//i.test(lugar);
    const datos = { cliente: el.dataset.id, titulo: $('agt').value.trim(), inicio: ini.toISOString(), minutos: Number($('agd').value), meet: $('agm').checked && !esEnlace, invitar: !!($('agi') && $('agi').checked), enlace: esEnlace ? lugar : '', lugar: esEnlace ? '' : lugar };
    cerrarDialogo(); encolar('AGENDAR_REUNION', datos, 'Agendada para ' + fmtHora(datos.inicio) + (datos.invitar ? '; se invitará al cliente' : ''));
  },
  prep(el) {
    const r = reuniones().find(x => x.id === el.dataset.id); if (!r) return; const c = cliente(r.cli); if (!c) return;
    const u = enlace(r.u), res = (c.res || [])[0], ts = tareas().filter(t => t.cli === c.id), ops = oportunidades().filter(o => o.cli === c.id && CERRADAS.indexOf(o.e) < 0);
    const sec = (t, h) => h ? '<h4 style="margin:12px 0 4px">' + t + '</h4>' + h : '';
    dialogo('<h3>' + esc(c.n) + '</h3><p class="gris">' + esc(r.t) + ' · ' + esc(fmtHora(r.f)) + '</p>' + (u ? '<a class="b p ancho" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">Unirse a ' + nombreVideo(u) + '</a>' : '') + '<div style="max-height:62vh;overflow:auto">' +
      sec('Qué necesita', c.nec ? '<p class="texto">' + esc(c.nec) + '</p>' : '') + sec('Objeciones', c.obj ? '<p class="texto">' + esc(c.obj) + '</p>' : '') + sec('Perfil pensional', c.pp ? '<p class="texto">' + esc(c.pp) + '</p>' : '') +
      sec('La última vez (' + (res ? fmtDia(res.f) : '') + ')', res ? '<p class="texto">' + esc(res.ej) + '</p>' + (res.p ? '<p><b>Próximos pasos</b><br>' + esc(res.p) + '</p>' : '') : '') +
      sec('Compromisos abiertos', (c.com || []).length ? c.com.map(k => '<div class="fila"><span>' + esc(k.d) + '</span><span class="gris peq">' + fmtDia(k.f) + '</span></div>').join('') : '') +
      sec('Tus tareas con él', ts.length ? ts.map(t => '<div class="fila"><span>' + esc(t.d) + '</span><span class="gris peq">' + fmtDia(t.v) + '</span></div>').join('') : '') +
      sec('Oportunidades', ops.length ? ops.map(o => '<div class="fila"><span>' + esc(o.n) + '</span><span class="gris peq">' + esc(o.e) + '</span></div>').join('') : '') +
      sec('Documentos que faltan', (c.df || []).length ? c.df.map(t => '<span class="etq mal">' + esc(String(t).replace(/_/g, ' ').toLowerCase()) + '</span>').join('') : '') +
      sec('Últimos contactos', (c.his || []).slice(0, 3).map(h => '<p class="peq"><b>' + fmtDia(h.f) + ' · ' + esc(h.c) + '</b><br>' + esc(String(h.r || h.a).slice(0, 220)) + '</p>').join('')) +
      '</div><div class="acc"><button class="b" data-a="ficha" data-id="' + esc(c.id) + '">Ver ficha</button><button class="b" data-a="cerrarD">Cerrar</button></div>');
  },
  // ----- Contacto -----
  editar(el) {
    const c = cliente(el.dataset.id); if (!c) return;
    const campo = (k, et, tipo, extra) => '<label for="ed_' + k + '">' + et + '</label>' + (tipo === 'area' ? '<textarea id="ed_' + k + '" data-k="' + k + '" rows="3">' + esc(c[MAPA_CAMPOS[k]] || '') + '</textarea>' : '<input id="ed_' + k + '" data-k="' + k + '" type="' + (tipo || 'text') + '" value="' + esc(c[MAPA_CAMPOS[k]] || '') + '"' + (extra || '') + '>');
    dialogo('<h3>Editar contacto</h3><div style="max-height:62vh;overflow:auto">' + campo('NOMBRE_COMPLETO', 'Nombre completo') + campo('TELEFONO_PRINCIPAL', 'Teléfono principal (con indicativo)', 'tel') + campo('WHATSAPP', 'WhatsApp, si es otro número', 'tel') + campo('CORREO_PRINCIPAL', 'Correo principal', 'email', ' autocapitalize="off"') + campo('CIUDAD', 'Ciudad') + campo('CARGO', 'Cargo o empresa') +
      '<label for="ed_ESTADO_CLIENTE">Estado</label><select id="ed_ESTADO_CLIENTE" data-k="ESTADO_CLIENTE">' + ((S.datos.estados) || []).map(s => '<option value="' + esc(s) + '"' + (c.s === s ? ' selected' : '') + '>' + esc(s.replace(/_/g, ' ').toLowerCase()) + '</option>').join('') + '</select>' +
      campo('FECHA_NACIMIENTO', 'Fecha de nacimiento', 'date') + campo('NECESIDAD_PRINCIPAL', 'Qué necesita', 'area') + campo('OBJECIONES', 'Objeciones', 'area') + campo('PROXIMA_ACCION', 'Próxima acción') + campo('FECHA_PROXIMO_CONTACTO', 'Próximo contacto', 'date') + campo('NOTAS', 'Notas', 'area') +
      '</div><div id="ederr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="guardarEd" data-id="' + esc(c.id) + '">Guardar</button></div>');
  },
  guardarEd(el) {
    const id = el.dataset.id, c = cliente(id), base0 = crudo(id) || {}, campos = {}, base = {};
    document.querySelectorAll('.dialogo [data-k]').forEach(i => { const k = i.dataset.k, v = i.value.trim(); if (v !== String(c[MAPA_CAMPOS[k]] || '')) { campos[k] = v; base[k] = String(base0[MAPA_CAMPOS[k]] || ''); } });
    if (campos.NOMBRE_COMPLETO === '') { $('ederr').textContent = 'El nombre no puede quedar vacío.'; return; }
    if (campos.CORREO_PRINCIPAL && !/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(campos.CORREO_PRINCIPAL)) { $('ederr').textContent = 'Revisa el correo.'; return; }
    if (!Object.keys(campos).length) { cerrarDialogo(); avisar('Sin cambios'); return; }
    cerrarDialogo(); encolar('EDITAR_CONTACTO', { cliente: id, campos, base }, 'Contacto actualizado');
  },
  foto(el) {
    const c = cliente(el.dataset.id); if (!c) return;
    dialogo('<h3>Documento de ' + esc(c.n) + '</h3><label for="fdn">Qué documento es</label><input id="fdn" placeholder="Por ejemplo: Cédula, historia laboral" maxlength="80"><label for="fdf">Foto o PDF</label><input id="fdf" type="file" accept="image/*,application/pdf"><p class="gris peq">Se guarda en su expediente del CRM, queda por revisar y la lectura automática lo clasifica. Requiere internet.</p><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="fotoYa" data-id="' + esc(c.id) + '">Enviar</button></div>');
  },
  async fotoYa(el) { const f = $('fdf').files[0], n = $('fdn').value.trim(), b = el; b.disabled = true; b.textContent = 'Enviando…'; if (await subirArchivo(f, 'DOCUMENTO', el.dataset.id, n)) cerrarDialogo(); else { b.disabled = false; b.textContent = 'Enviar'; } },
  tarjeta() { dialogo('<h3>Escanear tarjeta de presentación</h3><label for="tjf">Toma la foto de la tarjeta</label><input id="tjf" type="file" accept="image/*" capture="environment"><p class="gris peq">El CRM lee el nombre, el correo y el teléfono y te propone el prospecto en Revisión. Tú confirmas antes de crearlo.</p><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="tarjetaYa">Enviar</button></div>'); },
  async tarjetaYa(el) { el.disabled = true; el.textContent = 'Enviando…'; if (await subirArchivo($('tjf').files[0], 'TARJETA', '', 'Tarjeta')) cerrarDialogo(); else { el.disabled = false; el.textContent = 'Enviar'; } },
  // ----- Unificar -----
  unificar(el) { dialogo('<h3>Unificar con otro contacto</h3><p class="gris peq">Busca el otro registro de esta misma persona.</p><input id="uq" type="search" autocomplete="off" data-e="buscarU" data-id="' + esc(el.dataset.id) + '"><div id="us"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button></div>'); $('uq').focus(); },
  confirmarU(el) {
    const a = cliente(el.dataset.ca), b = cliente(el.dataset.cb); if (!a || !b) return;
    const dat = c => '<div class="card"><b>' + esc(c.n) + '</b><br><span class="gris peq">' + esc([(c.tel || []).join(', '), (c.mail || []).join(', ')].filter(Boolean).join(' · ') || 'Sin datos de contacto') + '</span></div>';
    dialogo('<h3>¿Son la misma persona?</h3>' + dat(a) + dat(b) + '<p class="gris peq">Sus datos, historial, reuniones y tareas quedan en una sola ficha. No se borra nada y se puede revertir desde el CRM. Elige cuál queda como principal:</p><div class="acc"><button class="b p" data-a="unificarYa" data-p="' + esc(a.id) + '" data-x="' + esc(b.id) + '">Queda ' + esc(a.n) + '</button><button class="b p" data-a="unificarYa" data-p="' + esc(b.id) + '" data-x="' + esc(a.id) + '">Queda ' + esc(b.n) + '</button>' + (el.dataset.par ? '<button class="b" data-a="sonDistintos" data-ca="' + esc(a.id) + '" data-cb="' + esc(b.id) + '">Son personas distintas</button>' : '') + '<button class="b" data-a="cerrarD">Cancelar</button></div>');
  },
  unificarYa(el) { const p = el.dataset.p, x = el.dataset.x; cerrarDialogo(); encolar('UNIFICAR', { principal: p, absorbido: x }, 'Contactos unificados'); if (S.vista === 'ficha' && S.pila[S.pila.length - 1] === x) { S.pila[S.pila.length - 1] = p; pintar(); } },
  sonDistintos(el) { cerrarDialogo(); encolar('SON_DISTINTOS', { a: el.dataset.ca, b: el.dataset.cb }, 'Quedan como personas distintas'); },
  verRep() {
    const l = repetidos();
    dialogo('<h3>Posibles repetidos</h3><p class="gris peq">El CRM encontró estos pares con el mismo correo o teléfono.</p><div style="max-height:62vh;overflow:auto">' + (l.length ? l.map(p => { const a = cliente(p.a), b = cliente(p.b); return '<button class="card tocable" data-a="confirmarU" data-par="1" data-ca="' + esc(p.a) + '" data-cb="' + esc(p.b) + '"><b>' + esc(a.n) + '</b> y <b>' + esc(b.n) + '</b><br><span class="gris peq">' + esc(p.m) + '</span></button>'; }).join('') : '<p class="gris">No quedan pares por revisar.</p>') + '</div><div class="acc"><button class="b" data-a="cerrarD">Cerrar</button></div>');
  },
  // ----- Embudo -----
  verEtapa(el) { S.etapa = el.dataset.e || ''; pintar(); },
  moverO(el) {
    const o = oportunidades().find(x => x.id === el.dataset.id); if (!o) return;
    dialogo('<h3>Mover de etapa</h3><p class="gris">' + esc(o.n) + ' · ' + esc(nombreCli(o.cli)) + '</p><div style="max-height:55vh;overflow:auto">' + etapasAbiertas().concat(['Ganado', 'Perdido']).map(e => '<button class="b ancho' + (e === o.e ? ' p' : '') + '" style="margin:3px 0" data-a="moverYa" data-id="' + esc(o.id) + '" data-e="' + esc(e) + '"' + (e === o.e ? ' disabled' : '') + '>' + esc(e) + '</button>').join('') + '</div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button></div>');
  },
  moverYa(el) {
    const o = oportunidades().find(x => x.id === el.dataset.id), e = el.dataset.e; if (!o || !e) return;
    if (e === 'Perdido' && !el.dataset.ok) { dialogo('<h3>¿Por qué se perdió?</h3><input id="mpm" placeholder="Precio, tiempo, eligió a otro…" maxlength="200"><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="moverYa" data-ok="1" data-id="' + esc(o.id) + '" data-e="Perdido">Guardar</button></div>'); return; }
    const base = ((S.datos.clientes.find(c => c.id === o.cli) || {}).op || []).find(x => x.id === o.id);
    const motivo = $('mpm') ? $('mpm').value.trim() : '';
    cerrarDialogo(); encolar('MOVER_ETAPA', { opo: o.id, etapa: e, base: base ? base.e : '', nombre: o.n, motivo }, 'Movida a ' + e);
  },
  nuevaO(el) {
    const id = el.dataset.id || '';
    dialogo('<h3>Nueva oportunidad</h3>' + (id ? '<p class="gris">Cliente: ' + esc(nombreCli(id)) + '</p><input type="hidden" id="oc" value="' + esc(id) + '">' : '<label for="oq">Cliente</label><input id="oq" type="search" autocomplete="off" data-e="buscarNO"><input type="hidden" id="oc"><div id="os"></div>') + '<label for="on">Nombre</label><input id="on" maxlength="150" value="' + esc(id ? nombreCli(id) : '') + '"><label for="osv">Servicio</label><select id="osv"><option value="">Sin definir</option>' + ((S.datos.servicios) || []).map(s => '<option value="' + esc(s.id) + '">' + esc(s.n) + '</option>').join('') + '</select><label for="oe">Etapa</label><select id="oe">' + etapasAbiertas().map(e => '<option>' + esc(e) + '</option>').join('') + '</select><label for="ov">Valor en COP (opcional)</label><input id="ov" type="number" min="0" inputmode="numeric"><div id="oerr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="crearO">Guardar</button></div>');
  },
  elegirO(el) { $('oc').value = el.dataset.id; $('oq').value = el.textContent; $('os').innerHTML = ''; if (!$('on').value) $('on').value = el.textContent; },
  crearO() {
    const cli = $('oc').value, n = $('on').value.trim(); if (!cli) { $('oerr').textContent = 'Elige el cliente.'; return; } if (!n) { $('oerr').textContent = 'Ponle un nombre.'; return; }
    cerrarDialogo(); encolar('CREAR_OPORTUNIDAD', { cliente: cli, nombre: n, etapa: $('oe').value, valor: $('ov').value, servicio: $('osv').value }, 'Oportunidad creada');
  },
  // ----- Face ID -----
  bioOn() { dialogo('<h3>Desbloquear con Face ID</h3><p class="gris peq">Escribe tu PIN una vez para guardarlo protegido por Face ID. El PIN seguirá funcionando siempre.</p><input id="bp" class="pin" type="password" inputmode="numeric" maxlength="6" autocomplete="current-password"><div id="berr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="bioOnYa">Activar</button></div>'); $('bp').focus(); },
  async bioOnYa(el) {
    const pin = $('bp').value; el.disabled = true;
    try { const clave = await derivar(pin, await kvLeer('sal')); await leer('sesion', clave); }
    catch (e) { $('berr').textContent = 'PIN incorrecto.'; el.disabled = false; return; }
    try { await activarBio(pin); cerrarDialogo(); avisar('Face ID activado'); pintar(); }
    catch (e) { await kvPoner('bio', null); $('berr').textContent = e.message === 'SIN_PRF' ? 'Este iPhone no permite Face ID para esta app (requiere iOS 18 o posterior). Sigue con el PIN.' : 'No se activó: ' + (e.name === 'NotAllowedError' ? 'cancelaste o Face ID no respondió.' : e.message); el.disabled = false; }
  },
  async bioOff() { await kvPoner('bio', null); avisar('Face ID desactivado'); pintar(); },
  bioEntrar() { entrarBio(); },
  nota(el) { dialogo('<h3>Nota para ' + esc(nombreCli(el.dataset.id)) + '</h3><label for="nt">Nota</label><textarea id="nt" rows="5" maxlength="3000"></textarea><div id="nterr" class="err"></div><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b p" data-a="guardarN" data-id="' + esc(el.dataset.id) + '">Guardar nota</button></div>'); $('nt').focus(); },
  guardarN(el) { const t = $('nt').value.trim(); if (!t) { $('nterr').textContent = 'Escribe la nota.'; return; } cerrarDialogo(); encolar('AGREGAR_NOTA', { cliente: el.dataset.id, texto: t }, 'Nota guardada'); },
  async quitarAviso(el) { S.avisos = S.avisos.filter(a => a.id !== el.dataset.id); await guardarCola(); pintar(); },
  bloquear() { bloquear(); },
  desvincular() {
    const n = S.cola.length;
    dialogo('<h3>Borrar datos de este dispositivo</h3><p>Se borra todo lo guardado aquí. Para volver a usar la app tendrás que vincularla con un código nuevo.</p>' + (n ? '<p class="err">Hay ' + n + (n === 1 ? ' cambio que aún no se confirma y se perdería.' : ' cambios que aún no se confirman y se perderían.') + '</p>' : '') + '<p class="gris">Revoca también este dispositivo en Automatización del CRM.</p><div class="acc"><button class="b" data-a="cerrarD">Cancelar</button><button class="b mal" data-a="borrarTodo">Borrar</button></div>');
  },
  async borrarTodo() { cerrarDialogo(); await kvVaciar(); location.reload(); },
  instaladaSeguir() { S.saltarInstalar = true; arranque(); }
};
document.addEventListener('click', e => {
  const el = e.target.closest('[data-a]'); if (!el) return;
  const f = A[el.dataset.a]; if (f) { e.preventDefault(); f(el); }
});
document.addEventListener('input', e => {
  const k = e.target.dataset.e;
  if (k === 'buscar') { S.busqueda = e.target.value; $('lc').innerHTML = listaCli(); }
  if (k === 'buscarU') { const q = e.target.value, yo = e.target.dataset.id; $('us').innerHTML = q.length < 2 ? '' : buscarCli(q, 8).lista.filter(c => c.id !== yo).map(c => '<button class="card tocable" data-a="confirmarU" data-ca="' + esc(yo) + '" data-cb="' + esc(c.id) + '"><b>' + esc(c.n) + '</b><br><span class="gris peq">' + esc((c.tel && c.tel[0]) || (c.mail && c.mail[0]) || '') + '</span></button>').join('') || '<p class="gris">Sin coincidencias</p>'; }
  if (k === 'buscarNO') { const q = e.target.value; $('oc').value = ''; $('os').innerHTML = q.length < 2 ? '' : buscarCli(q, 6).lista.map(c => '<button class="b" data-a="elegirO" data-id="' + esc(c.id) + '">' + esc(c.n) + '</button> ').join(''); }
  if (k === 'buscarNT') { const q = e.target.value; $('nc').value = ''; $('ns').innerHTML = q.length < 2 ? '' : buscarCli(q, 6).lista.map(c => '<button class="b" data-a="elegirC" data-id="' + esc(c.id) + '">' + esc(c.n) + '</button> ').join(''); }
});

/* ---------- Instalación, vinculación y PIN ---------- */
const esIOS = () => /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const instalada = () => window.navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
function pInstalar() {
  $('raiz').innerHTML = '<div class="pantalla"><img class="marca" src="icono-192.png" alt=""><h1>Instala OI CRM</h1><p class="gris">En iPhone debes instalarla antes de vincularla: Safari y la app instalada no comparten datos.</p><ol class="pasos"><li>Toca <b>Compartir</b> en la barra de Safari.</li><li>Elige <b>Añadir a pantalla de inicio</b> y luego <b>Añadir</b>.</li><li>Cierra Safari y abre <b>OI CRM</b> desde su ícono.</li></ol></div>';
}
function pVincular() {
  $('raiz').innerHTML = '<div class="pantalla"><img class="marca" src="icono-192.png" alt=""><h1>Vincular este dispositivo</h1><p class="gris">En el CRM, abre Automatización y toca «Vincular dispositivo».</p><label for="vc">Código de vinculación</label><input id="vc" class="codigo" autocomplete="one-time-code" autocapitalize="characters" maxlength="14" placeholder="XXXX-XXXX-XXXX"><label for="vn">Nombre de este dispositivo</label><input id="vn" value="' + (esIOS() ? 'iPhone' : 'Mi computador') + '" maxlength="60"><label for="vp">Crea un PIN de 6 dígitos</label><input id="vp" class="pin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="new-password"><label for="vp2">Repite el PIN</label><input id="vp2" class="pin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="new-password"><div id="verr" class="err"></div><button class="b p ancho" id="vok">Vincular</button><p class="gris peq">El PIN cifra los datos en este dispositivo. Si lo olvidas, se vincula de nuevo sin perder nada del CRM.</p></div>';
  $('vok').onclick = vincular;
}
async function vincular() {
  const cod = $('vc').value.trim(), pin = $('vp').value, err = $('verr'), b = $('vok');
  err.textContent = '';
  if (!/^\d{6}$/.test(pin)) { err.textContent = 'El PIN debe tener 6 dígitos.'; return; }
  if (/^(\d)\1{5}$/.test(pin) || pin === '123456' || pin === '654321') { err.textContent = 'Ese PIN es muy fácil de adivinar.'; return; }
  if (pin !== $('vp2').value) { err.textContent = 'Los PIN no coinciden.'; return; }
  if (cod.replace(/[^A-Za-z0-9]/g, '').length !== 12) { err.textContent = 'El código tiene 12 caracteres.'; return; }
  if (navigator.onLine === false) { err.textContent = 'Vincular requiere internet.'; return; }
  b.disabled = true; b.textContent = 'Vinculando…';
  try {
    const nombre = $('vn').value.trim() || 'Dispositivo', r = await llamar({ accion: 'vincular', codigo: cod, nombre });
    if (!r.ok) throw new Error({ CODIGO_INVALIDO: 'Código incorrecto o vencido. Genera otro en el CRM.', BLOQUEADO: 'Demasiados intentos. Espera 15 minutos.', OCUPADO: 'El CRM está ocupado. Intenta de nuevo.' }[r.error] || 'No se pudo vincular. Intenta de nuevo.');
    const sal = crypto.getRandomValues(new Uint8Array(16));
    S.clave = await derivar(pin, sal);
    S.sesion = { token: r.token, dispositivo: r.dispositivo, nombre };
    await kvPoner('sal', sal); await kvPoner('fallos', 0); await guardar('sesion', S.sesion); await guardarCola();
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => { });
    S.vista = 'dia'; pintar(); await sincronizar();
  } catch (e) {
    S.clave = null; S.sesion = null; b.disabled = false; b.textContent = 'Vincular';
    err.textContent = e.name === 'TypeError' || e.name === 'AbortError' ? 'Sin conexión con el CRM. Revisa internet.' : e.message;
  }
}
function pPin(msg) {
  $('raiz').innerHTML = '<div class="pantalla"><img class="marca" src="icono-192.png" alt=""><h1>OI CRM</h1><label for="pp">Escribe tu PIN</label><input id="pp" class="pin" type="password" inputmode="numeric" pattern="[0-9]*" maxlength="6" autocomplete="current-password"><div id="perr" class="err">' + esc(msg || '') + '</div><button class="b p ancho" id="pok">Entrar</button></div>';
  $('pok').onclick = entrar; $('pp').addEventListener('input', e => { if (e.target.value.length === 6) entrar(); }); $('pp').focus();
  // Face ID necesita que toques el botón: el iPhone no lo abre solo.
  kvLeer('bio').then(b => { if (b && $('pok')) $('pok').insertAdjacentHTML('afterend', '<button class="b ancho" style="margin-top:8px" data-a="bioEntrar">Entrar con Face ID</button>'); }).catch(() => { });
}
let entrando = false;
async function entrar() {
  if (entrando) return; entrando = true;
  const pin = $('pp').value, err = $('perr');
  try {
    const sal = await kvLeer('sal'), clave = await derivar(pin, sal);
    S.sesion = await leer('sesion', clave); S.clave = clave;
    await kvPoner('fallos', 0);
    S.datos = await leer('datos'); const c = await leer('cola') || {}; S.cola = c.cola || []; S.avisos = c.avisos || []; S.ultima = await leer('ultima') || '';
    S.bioActivo = !!(await kvLeer('bio')); S.bioPuede = await bioDisponible();
    S.vista = 'dia'; S.pila = []; pintar(); sincronizar();
  } catch (e) {
    S.clave = null;
    const n = (await kvLeer('fallos') || 0) + 1;
    if (n >= MAX_FALLOS) { await kvVaciar(); location.reload(); return; }
    await kvPoner('fallos', n); $('pp').value = '';
    err.textContent = 'PIN incorrecto.' + (n >= 5 ? ' Tras ' + (MAX_FALLOS - n) + ' intentos más se borrarán los datos de este dispositivo.' : '');
  } finally { entrando = false; }
}
function bloquear() {
  clearTimeout(temporizador); cerrarDialogo();
  Object.assign(S, { clave: null, datos: null, cola: [], avisos: [], sesion: null, busqueda: '', pila: [] });
  pPin();
}
document.addEventListener('visibilitychange', () => {
  if (document.hidden) { S.ocultoDesde = Date.now(); return; }
  if (S.clave && S.ocultoDesde && Date.now() - S.ocultoDesde > BLOQUEO_MS) { bloquear(); return; }
  if (S.clave) sincronizar();
});
window.addEventListener('online', () => { S.red = 'ok'; sincronizar(); });
window.addEventListener('offline', () => { S.red = 'fuera'; pintarEstado(); });
setInterval(() => { if (S.clave && !document.hidden) sincronizar(); }, 5 * 60000);
async function arranque() {
  if ('serviceWorker' in navigator) {
    // Busca una versión nueva cada vez que abre y, cuando la instala, recarga una sola vez para mostrarla.
    const yaHabia = !!navigator.serviceWorker.controller;
    navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' }).then(r => r.update()).catch(() => { });
    let recargada = false;
    navigator.serviceWorker.addEventListener('controllerchange', () => { if (yaHabia && !recargada && !S.clave) { recargada = true; location.reload(); } });
  }
  if (!window.crypto || !crypto.subtle || !window.indexedDB) { $('raiz').innerHTML = '<div class="pantalla"><h1>Navegador no compatible</h1><p>Abre la app con una dirección https en Safari o Chrome.</p></div>'; return; }
  const sal = await kvLeer('sal');
  if (sal) pPin();
  else if (esIOS() && !instalada()) pInstalar();
  else pVincular();
}
arranque();
