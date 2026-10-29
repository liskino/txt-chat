/**
 * txt-chat — редактор txt + чат + база зарегистрированных.
 *
 * Ноль зависимостей: Node.js (http, crypto, fs) — всё встроенное.
 * Данные: data/db.json — пользователи, чаты, сообщения, txt-файлы.
 *
 * Запуск: node server.mjs   (порт задаётся переменной PORT)
 */
import { createServer } from 'node:http'
import { readFile, writeFile, mkdir, stat } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { join, resolve, normalize } from 'node:path'
import { randomUUID, scryptSync, randomBytes, timingSafeEqual } from 'node:crypto'

const PORT = Number(process.env.PORT || 4322)
const HOST = process.env.HOST || '0.0.0.0'
const ROOT = process.cwd()
const DATA = resolve(process.env.TXTCHAT_DIR || join(ROOT, 'data'))
const DIST = resolve(process.env.TXTCHAT_CLIENT_DIR || join(ROOT, 'public'))

// ─────────────────────────── база данных ───────────────────────────
//
// Один JSON-файл. Для мессенджера на небольшой круг людей этого достаточно,
// а читать глазами (кто зарегистрирован) проще простого.

const DB_FILE = join(DATA, 'db.json')

const db = {
  users: [],      // { id, email, name, passHash, salt, createdAt }
  sessions: {},   // token -> { userId, createdAt }
  messages: [],   // { id, userId, name, text, createdAt }
  files: {},      // fileId -> { id, name, text, userId, createdAt, updatedAt }
}

async function loadDb() {
  if (existsSync(DB_FILE)) {
    try {
      Object.assign(db, JSON.parse(await readFile(DB_FILE, 'utf8')))
    } catch (e) {
      console.error('База повреждена, создаём новую:', e.message)
    }
  }
}

let saveTimer = null
function saveDb() {
  // Запись с задержкой 200 мс: спам сообщениями не должен молотить диск.
  clearTimeout(saveTimer)
  saveTimer = setTimeout(async () => {
    try {
      await writeFile(DB_FILE, JSON.stringify(db, null, 2), 'utf8')
    } catch (e) {
      console.error('Не удалось сохранить базу:', e.message)
    }
  }, 200)
}

// ─────────────────────────── пароли ───────────────────────────
//
// scrypt из состава Node.js + соль на пользователя. Пароли в базе
// не хранятся в открытом виде.

function hashPassword(password, salt) {
  return scryptSync(password, salt, 64).toString('hex')
}

function checkPassword(user, password) {
  const hash = Buffer.from(hashPassword(password, user.salt), 'hex')
  const stored = Buffer.from(user.passHash, 'hex')
  return hash.length === stored.length && timingSafeEqual(hash, stored)
}

// ─────────────────────────── ответы ───────────────────────────

function json(res, status, body) {
  const data = JSON.stringify(body)
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(data),
    'Cache-Control': 'no-store',
  })
  res.end(data)
}

function fail(res, status, message, code) {
  json(res, status, { error: message, code })
}

async function readJson(req) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > 1024 * 1024) throw new Error('Слишком большой запрос')
    chunks.push(chunk)
  }
  if (!chunks.length) return {}
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'))
  } catch {
    throw new Error('Некорректный JSON')
  }
}

function tokenOf(req) {
  const header = req.headers.authorization
  if (header?.startsWith('Bearer ')) return header.slice(7)
  return null
}

function userOf(req) {
  const s = db.sessions[tokenOf(req)]
  if (!s) return null
  return db.users.find((u) => u.id === s.userId) || null
}

function publicUser(u) {
  return { id: u.id, name: u.name, email: u.email, createdAt: u.createdAt }
}

// ─────────────────────────── API ───────────────────────────

const routes = []
function route(method, path, handler) {
  routes.push({ method, path, handler })
}

// Регистрация — отсюда и растёт база людей.
route('POST', '/api/auth/register', async (req, res, body) => {
  const email = String(body.email || '').trim().toLowerCase()
  const name = String(body.name || '').trim()
  const password = String(body.password || '')

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return fail(res, 400, 'Некорректный email')
  if (name.length < 2 || name.length > 40) return fail(res, 400, 'Имя: 2–40 символов')
  if (password.length < 6) return fail(res, 400, 'Пароль: минимум 6 символов')
  if (db.users.some((u) => u.email === email)) return fail(res, 409, 'Этот email уже зарегистрирован')

  const salt = randomBytes(16).toString('hex')
  const user = {
    id: randomUUID(),
    email,
    name,
    salt,
    passHash: hashPassword(password, salt),
    createdAt: Date.now(),
  }
  db.users.push(user)

  const token = randomUUID()
  db.sessions[token] = { userId: user.id, createdAt: Date.now() }
  saveDb()
  json(res, 201, { token, user: publicUser(user) })
})

route('POST', '/api/auth/login', async (req, res, body) => {
  const email = String(body.email || '').trim().toLowerCase()
  const password = String(body.password || '')
  const user = db.users.find((u) => u.email === email)
  if (!user || !checkPassword(user, password)) return fail(res, 401, 'Неверный email или пароль')
  const token = randomUUID()
  db.sessions[token] = { userId: user.id, createdAt: Date.now() }
  saveDb()
  json(res, 200, { token, user: publicUser(user) })
})

route('POST', '/api/auth/logout', async (req, res) => {
  const token = tokenOf(req)
  if (token) delete db.sessions[token]
  saveDb()
  json(res, 200, { ok: true })
})

route('GET', '/api/me', async (req, res) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  json(res, 200, { user: publicUser(user) })
})

// База зарегистрированных: кто есть, кто когда пришёл.
route('GET', '/api/users', async (req, res) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const users = db.users
    .map(publicUser)
    .sort((a, b) => a.createdAt - b.createdAt)
  json(res, 200, { users, total: users.length })
})

// Сообщения общего чата.
route('GET', '/api/messages', async (req, res) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const after = 0
  json(res, 200, { messages: db.messages.slice(-200) })
})

route('POST', '/api/messages', async (req, res, body) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const text = String(body.text || '')
  if (!text.trim()) return fail(res, 400, 'Пустое сообщение')
  if (text.length > 10000) return fail(res, 400, 'Сообщение слишком длинное')
  const msg = { id: randomUUID(), userId: user.id, name: user.name, text, createdAt: Date.now() }
  db.messages.push(msg)
  if (db.messages.length > 5000) db.messages = db.messages.slice(-5000)
  saveDb()
  broadcast({ type: 'message', message: msg })
  json(res, 201, { message: msg })
})

// «Отправить txt как сообщение» — файл целиком уходит в чат.
route('POST', '/api/files/:id/send', async (req, res, body, { id }) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const file = db.files[id]
  if (!file) return fail(res, 404, 'Файл не найден')
  const text = `📄 ${file.name}\n${file.text}`
  if (text.length > 10000) return fail(res, 400, 'Файл слишком большой для отправки (предел 10 000 символов)')
  const msg = { id: randomUUID(), userId: user.id, name: user.name, text, file: { id, name: file.name }, createdAt: Date.now() }
  db.messages.push(msg)
  saveDb()
  broadcast({ type: 'message', message: msg })
  json(res, 201, { message: msg })
})

// txt-файлы: каждый пользователь имеет свои.
route('GET', '/api/files', async (req, res) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const files = Object.values(db.files)
    .filter((f) => f.userId === user.id)
    .map((f) => ({ id: f.id, name: f.name, size: f.text.length, createdAt: f.createdAt, updatedAt: f.updatedAt }))
    .sort((a, b) => b.updatedAt - a.updatedAt)
  json(res, 200, { files })
})

route('POST', '/api/files', async (req, res, body) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const name = String(body.name || '').trim() || 'Новый файл.txt'
  const text = String(body.text ?? '')
  if (name.length > 100) return fail(res, 400, 'Слишком длинное имя')
  if (text.length > 500000) return fail(res, 400, 'Файл слишком большой')
  const file = { id: randomUUID(), name, text, userId: user.id, createdAt: Date.now(), updatedAt: Date.now() }
  db.files[file.id] = file
  saveDb()
  json(res, 201, { file })
})

route('GET', '/api/files/:id', async (req, res, body, { id }) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const file = db.files[id]
  if (!file || file.userId !== user.id) return fail(res, 404, 'Файл не найден')
  json(res, 200, { file })
})

route('PUT', '/api/files/:id', async (req, res, body, { id }) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const file = db.files[id]
  if (!file || file.userId !== user.id) return fail(res, 404, 'Файл не найден')
  if (body.name !== undefined) {
    const name = String(body.name || '').trim()
    if (!name) return fail(res, 400, 'Имя не может быть пустым')
    file.name = name
  }
  if (body.text !== undefined) {
    const text = String(body.text ?? '')
    if (text.length > 500000) return fail(res, 400, 'Файл слишком большой')
    file.text = text
  }
  file.updatedAt = Date.now()
  saveDb()
  json(res, 200, { file })
})

route('DELETE', '/api/files/:id', async (req, res, body, { id }) => {
  const user = userOf(req)
  if (!user) return fail(res, 401, 'Требуется вход')
  const file = db.files[id]
  if (!file || file.userId !== user.id) return fail(res, 404, 'Файл не найден')
  delete db.files[id]
  saveDb()
  json(res, 200, { ok: true })
})

route('GET', '/api/health', async (req, res) => {
  json(res, 200, { ok: true, name: 'txt-chat', users: db.users.length, messages: db.messages.length })
})

// ─────────────────────────── живые события (SSE) ───────────────────────────

const sseClients = new Set()

function broadcast(event) {
  const data = JSON.stringify(event)
  for (const client of sseClients) {
    try {
      client.write(`data: ${data}\n\n`)
    } catch {
      sseClients.delete(client)
    }
  }
}

// ─────────────────────────── статика ───────────────────────────

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
}

async function serveStatic(res, pathname) {
  if (!existsSync(DIST)) {
    return fail(res, 503, 'Клиент не собран: положите файлы в папку public/')
  }
  const requested = pathname === '/' ? '/index.html' : pathname
  const safe = normalize(requested).replace(/^([/\\])+/, '')
  let full = join(DIST, safe)
  if (!existsSync(full) || !statSyncIsFile(full)) full = join(DIST, 'index.html')
  if (!full.startsWith(DIST)) return fail(res, 403, 'Доступ запрещён')
  const info = await stat(full)
  const ext = full.slice(full.lastIndexOf('.'))
  res.writeHead(200, {
    'Content-Type': MIME[ext] ?? 'application/octet-stream',
    'Content-Length': info.size,
    'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=3600',
  })
  ;(await import('node:fs')).createReadStream(full).pipe(res)
}

function statSyncIsFile(full) {
  try {
    const { statSync } = require('node:fs')
    return statSync(full).isFile()
  } catch {
    return false
  }
}

// ─────────────────────────── роутер ───────────────────────────

function parseRoute(pattern) {
  const parts = pattern.split('/').filter(Boolean)
  return parts
}

async function handle(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`)

  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  if (req.method === 'OPTIONS') {
    res.writeHead(204)
    return res.end()
  }

  // SSE: живая доставка сообщений
  if (url.pathname === '/api/events') {
    const user = userOf(req)
    if (!user) return fail(res, 401, 'Требуется вход')
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-store',
      Connection: 'keep-alive',
    })
    res.write(': hello\n\n')
    sseClients.add(res)
    req.on('close', () => sseClients.delete(res))
    return
  }

  if (url.pathname.startsWith('/api/')) {
    const pathParts = url.pathname.split('/').filter(Boolean) // ['api', 'files', 'id', 'send']
    let body = {}
    if (req.method === 'POST' || req.method === 'PUT') {
      try {
        body = await readJson(req)
      } catch (e) {
        return fail(res, 400, e.message)
      }
    }
    for (const r of routes) {
      if (r.method !== req.method) continue
      const rp = parseRoute(r.path) // ['api', 'files', ':id', 'send']
      if (rp.length !== pathParts.length) continue
      const params = {}
      let ok = true
      for (let i = 0; i < rp.length; i++) {
        if (rp[i].startsWith(':')) params[rp[i].slice(1)] = decodeURIComponent(pathParts[i])
        else if (rp[i] !== pathParts[i]) { ok = false; break }
      }
      if (!ok) continue
      return r.handler(req, res, body, params)
    }
    return fail(res, 404, 'Не найдено', 'NOT_FOUND')
  }

  serveStatic(res, url.pathname)
}

// ─────────────────────────── запуск ───────────────────────────

await mkdir(DATA, { recursive: true })
await loadDb()

const server = createServer(async (req, res) => {
  try {
    await handle(req, res)
  } catch (e) {
    console.error(e)
    if (!res.headersSent) fail(res, 500, 'Ошибка сервера')
  }
})

server.listen(PORT, HOST, () => {
  console.log(`txt-chat: http://localhost:${PORT}`)
  console.log(`База: ${DB_FILE}`)
  console.log(`Зарегистрировано: ${db.users.length}`)
})
