/* OI CRM sin conexión. Todo lo guardado en el dispositivo va cifrado con una clave derivada del PIN. */
'use strict';
const PASARELA = (window.OI_CONFIG || {}).pasarela || '';
const VERSION_APP = '3';
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
const clientes = () => S.datos ? S.datos.clientes : [];
const cliente = id => clientes().find(c => c.id === id);
const nombreCli = id => { const c = cliente(id); return c ? c.n : ''; };
function ordenVence(a, b) { return (a.v || '9999').localeCompare(b.v || '9999'); }

/* ---------- Pintado ---------- */
const VISTAS = { dia: ['Mi día', vDia], tareas: ['Tareas', vTareas], clientes: ['Clientes', vClientes], sinc: ['Sincronizar', vSinc] };
function pintar() {
  const r = $('raiz'), ficha = S.vista === 'ficha', titulo = ficha ? (nombreCli(S.pila[S.pila.length - 1]) || 'Cliente') : VISTAS[S.vista][0];
  r.innerHTML = '<header class="cab">' + (ficha ? '<button class="volver" data-a="volver" aria-label="Volver">‹ Volver</button>' : '') + '<b>' + esc(titulo) + '</b><button class="estado" data-a="ir" data-v="sinc" id="est"></button></header><main id="m"></main><nav class="nav" aria-label="Secciones">' + ['dia', 'tareas', 'clientes', 'sinc'].map(v => '<button data-a="ir" data-v="' + v + '" class="' + (S.vista === v ? 'activo' : '') + '"' + (S.vista === v ? ' aria-current="page"' : '') + '>' + VISTAS[v][0] + '</button>').join('') + '</nav>';
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
function tarjetaReunion(r) {
  const u = enlace(r.u), cn = nombreCli(r.cli);
  return '<div class="card"><h3>' + esc(r.t || 'Reunión') + '</h3><span class="gris">' + esc(fmtHora(r.f)) + (cn ? ' · ' + esc(cn) : '') + '</span>' + (r.cli || u ? '<div class="acc">' + (r.cli ? '<button class="b" data-a="ficha" data-id="' + esc(r.cli) + '">Ver cliente</button>' : '') + (u ? '<a class="b" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">Abrir enlace</a>' : '') + '</div>' : '') + '</div>';
}
function avisosHtml() {
  if (!S.avisos.length) return '';
  return '<button class="card tocable" data-a="ir" data-v="sinc"><span class="etq mal">Atención</span> ' + S.avisos.length + (S.avisos.length === 1 ? ' cambio no se aplicó como esperabas' : ' cambios no se aplicaron como esperabas') + '</button>';
}
function vDia() {
  if (!S.datos) return '<div class="vacio">Aún no hay datos. Sincroniza con internet para descargarlos.</div>';
  const h = hoy(), ts = tareas(), venc = ts.filter(t => t.v && t.v < h).sort(ordenVence), deHoy = ts.filter(t => t.v === h);
  const rs = S.datos.reuniones.filter(r => { const d = new Date(r.f); return !isNaN(d) && d >= new Date(new Date().setHours(0, 0, 0, 0)); }).sort((a, b) => new Date(a.f) - new Date(b.f));
  const rHoy = rs.filter(r => fechaLocal(new Date(r.f)) === h), rProx = rs.filter(r => fechaLocal(new Date(r.f)) !== h && fechaLocal(new Date(r.f)) <= masDias(7));
  let x = '<h1>' + esc(new Date().toLocaleDateString('es-CO', { weekday: 'long', day: 'numeric', month: 'long' })) + '</h1>' + avisosHtml();
  x += '<div class="met"><button class="' + (venc.length ? 'malo' : '') + '" data-a="filtrar" data-f="vencidas"><strong>' + venc.length + '</strong><span>Vencidas</span></button><button data-a="filtrar" data-f="hoy"><strong>' + deHoy.length + '</strong><span>Para hoy</span></button><button data-a="filtrar" data-f="todas"><strong>' + ts.length + '</strong><span>Abiertas</span></button></div>';
  const cumples = clientes().map(c => ({ c, d: diasCumple(c.cu) })).filter(x => x.d !== null && x.d <= 7).sort((a, b) => a.d - b.d || a.c.n.localeCompare(b.c.n, 'es'));
  const cHoy = cumples.filter(x => x.d === 0), cProx = cumples.filter(x => x.d > 0);
  if (cHoy.length) x += '<h2>Cumpleaños de hoy</h2>' + cHoy.map(x2 => tarjetaCumple(x2.c, 0)).join('');
  x += '<h2>Reuniones de hoy</h2>' + (rHoy.length ? rHoy.map(tarjetaReunion).join('') : '<p class="gris">Ninguna reunión hoy.</p>');
  x += '<h2>Tareas de hoy</h2>' + (deHoy.length ? deHoy.map(tarjetaTarea).join('') : '<p class="gris">Nada programado para hoy.</p>');
  if (venc.length) x += '<h2>Vencidas</h2>' + venc.slice(0, 30).map(tarjetaTarea).join('') + (venc.length > 30 ? '<button class="b ancho" data-a="filtrar" data-f="vencidas">Ver las ' + venc.length + '</button>' : '');
  // Los más interesados sin ninguna tarea abierta: nadie los está atendiendo.
  const conTarea = {}; ts.forEach(t => { if (t.cli) conTarea[t.cli] = 1; });
  const intere = clientes().filter(c => (c.pi || 0) >= 50 && !conTarea[c.id] && c.s !== 'ACTIVO' && c.s !== 'PERDIDO').sort((a, b) => b.pi - a.pi).slice(0, 5);
  if (intere.length) x += '<h2>Interesados sin seguimiento</h2>' + intere.map(tarjetaInteres).join('');
  if (rProx.length) x += '<h2>Próximos 7 días</h2>' + rProx.map(tarjetaReunion).join('');
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
function vClientes() {
  return '<label for="q">Buscar por nombre, teléfono o correo</label><input id="q" type="search" autocomplete="off" autocapitalize="off" value="' + esc(S.busqueda) + '" data-e="buscar"><div id="lc">' + listaCli() + '</div>';
}
function vFicha(id) {
  const c = cliente(id); if (!c) return '<div class="vacio">Este cliente ya no está en los datos descargados.</div>';
  const ts = tareas().filter(t => t.cli === id).sort(ordenVence), rs = (S.datos.reuniones || []).filter(r => r.cli === id).sort((a, b) => new Date(b.f) - new Date(a.f));
  const notas = S.cola.filter(n => n.accion === 'AGREGAR_NOTA' && n.datos.cliente === id).map(n => ({ f: n.fecha.slice(0, 10), c: 'APP', a: 'Nota', r: n.datos.texto, pend: 1 })), his = notas.concat(c.his || []);
  const dc = diasCumple(c.cu), car = enlace(c.car);
  let x = '<h1>' + esc(c.n) + '</h1><span class="etq">' + esc(String(c.s || '').replace(/_/g, ' ')) + '</span>' + (c.ci ? '<span class="etq">' + esc(c.ci) + '</span>' : '') + etqInteres(c.pi) + (dc === 0 ? '<span class="etq oro">Cumple hoy</span>' : '') + String(c.et || '').split('|').map(t => t.trim()).filter(Boolean).map(t => '<span class="etq"># ' + esc(t) + '</span>').join('');
  x += '<div class="acc">' + botonesContacto(c, dc === 0 ? 'CUMPLE_HOY' : dc !== null && dc <= 7 ? 'CUMPLE_SEMANA' : '') + (car ? '<a class="b" target="_blank" rel="noopener noreferrer" href="' + esc(car) + '">Carpeta</a>' : '') + '</div>';
  x += '<div class="acc"><button class="b p" data-a="nuevaT" data-id="' + esc(id) + '">Nueva tarea</button><button class="b" data-a="nota" data-id="' + esc(id) + '">Agregar nota</button></div>';
  const cumpleTxt = c.cu ? new Date('2000-' + c.cu + 'T12:00:00').toLocaleDateString('es-CO', { day: 'numeric', month: 'long' }) + (dc === 0 ? ' (hoy)' : dc !== null ? ' (en ' + dc + (dc === 1 ? ' día)' : ' días)') : '') : '';
  const datos = [['Teléfonos', (c.tel || []).join(', ')], ['Correos', (c.mail || []).join(', ')], ['Cumpleaños', cumpleTxt], ['Relación', c.rc], ['Llegó por', c.fu], ['Interés', c.pi ? c.pi + '/100 · ' + (c.pm || '') : ''], ['Necesidad', c.nec], ['Objeciones', c.obj], ['Próxima acción', c.pa], ['Próximo contacto', c.fp ? fmtDia(c.fp) : ''], ['Notas', c.not]].filter(d => d[1]);
  if (datos.length) x += '<h2>Datos</h2><div class="card">' + datos.map(d => '<p><b>' + d[0] + '</b><br><span class="texto">' + esc(d[1]) + '</span></p>').join('') + '</div>';
  if (c.pp || c.pf) x += '<h2>Perfil</h2><div class="card">' + (c.pp ? '<p><b>Pensional</b><br><span class="texto">' + esc(c.pp) + '</span></p>' : '') + (c.pf ? '<p><b>Financiero</b><br><span class="texto">' + esc(c.pf) + '</span></p>' : '') + '</div>';
  if ((c.doc || []).length || c.ce) x += '<h2>Expediente</h2><div class="card">' + (c.ce ? '<p class="gris">' + (c.ce === 'VERIFICADA' ? 'Carpeta vinculada' : 'Carpeta con ruta histórica sin verificar') + '</p>' : '') + (c.doc || []).map(d => { const u = enlace(d.u); return '<div class="fila"><span>' + (u ? '<a target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">' + esc(d.n || 'Documento') + '</a>' : esc(d.n || 'Documento')) + (d.t ? ' <span class="gris peq">' + esc(String(d.t).replace(/_/g, ' ').toLowerCase()) + '</span>' : '') + '</span><span class="gris peq">' + (d.f ? fmtDia(d.f) : '') + '</span></div>'; }).join('') + '</div>';
  x += '<h2>Tareas abiertas</h2>' + (ts.length ? ts.map(tarjetaTarea).join('') : '<p class="gris">Sin tareas abiertas.</p>');
  if ((c.com || []).length) x += '<h2>Compromisos</h2><div class="card">' + c.com.map(k => '<div class="fila"><span>' + esc(k.d) + '</span><span class="gris peq">' + fmtDia(k.f) + '</span></div>').join('') + '</div>';
  if ((c.res || []).length) x += '<h2>Resúmenes de reuniones</h2><div class="card">' + c.res.map(r => { const u = enlace(r.u); return '<details><summary>' + esc(r.t) + ' · ' + fmtDia(r.f) + '</summary><p class="texto">' + esc(r.ej) + '</p>' + (r.n ? '<p><b>Necesidades</b><br>' + esc(r.n) + '</p>' : '') + (r.o ? '<p><b>Objeciones</b><br>' + esc(r.o) + '</p>' : '') + (r.p ? '<p><b>Próximos pasos</b><br>' + esc(r.p) + '</p>' : '') + (u ? '<a class="b" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">Ver grabación</a>' : '') + '</details>'; }).join('') + '</div>';
  if (rs.length) x += '<h2>Reuniones</h2><div class="card">' + rs.slice(0, 15).map(r => '<div class="fila"><span>' + esc(r.t) + '</span><span class="gris peq">' + esc(fmtHora(r.f)) + '</span></div>').join('') + '</div>';
  if (his.length) x += '<h2>Historial reciente</h2><div class="card">' + his.map(h => '<details><summary>' + fmtDia(h.f) + ' · ' + esc(h.c) + (h.pend ? ' · por confirmar' : '') + (h.q ? ' · espera respuesta' : '') + '</summary><p class="texto">' + esc(h.r || h.a) + '</p></details>').join('') + '</div>';
  return x;
}
function vSinc() {
  const gen = S.datos && S.datos.generado, env = S.cola.filter(c => c.estado === 'enviado').length, pen = S.cola.length - env;
  let x = '<div class="card"><p><b>' + (S.sincronizando ? 'Comprobando conexión…' : S.red === 'revocado' ? 'Este dispositivo fue revocado. Vuelve a vincularlo desde el CRM' : S.red === 'fuera' ? 'Sin conexión con el CRM' : 'Conectado') + '</b></p><p class="gris">Datos del CRM: ' + (gen ? esc(fmtHora(gen)) : 'sin descargar') + '<br>Última sincronización: ' + (S.ultima ? esc(fmtHora(S.ultima)) : 'nunca') + '</p><p class="gris">' + pen + ' por enviar · ' + env + ' enviados, esperando que el CRM los aplique (hasta 10 minutos)</p><button class="b p ancho" data-a="sync"' + (S.sincronizando || S.revocado ? ' disabled' : '') + '>' + (S.sincronizando ? 'Sincronizando…' : 'Sincronizar ahora') + '</button></div>';
  if (S.avisos.length) x += '<h2>Requieren tu atención</h2>' + S.avisos.map(a => '<div class="card"><span class="etq mal">' + (a.tipo === 'CONFLICTO' ? 'Conflicto' : 'No aplicado') + '</span><p>' + esc(a.texto) + '</p><p class="gris">' + esc(a.motivo) + (a.tipo === 'CONFLICTO' ? '. Quedó en Revisión del CRM.' : '') + '</p><button class="b" data-a="quitarAviso" data-id="' + esc(a.id) + '">Entendido</button></div>').join('');
  if (S.cola.length) x += '<h2>Cambios por confirmar</h2><div class="card">' + S.cola.map(c => '<div class="fila"><span>' + esc(describir(c)) + '</span><span class="gris peq">' + (c.estado === 'enviado' ? 'Enviado' : 'Por enviar') + '</span></div>').join('') + '</div>';
  x += '<h2>Este dispositivo</h2><div class="card"><p class="gris">' + esc(S.sesion && S.sesion.nombre || '') + ' · Versión de la app ' + VERSION_APP + '</p><div class="acc"><button class="b" data-a="bloquear">Bloquear ahora</button><button class="b mal" data-a="desvincular">Borrar datos de este dispositivo</button></div></div>';
  return x;
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
