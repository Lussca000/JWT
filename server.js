import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import cors from "cors";
import sqlite3 from "sqlite3";
import { open } from "sqlite";

const app = express();
app.use(express.json());
app.use(cors());

// Conectar ao SQLite
const db = await open({
  filename: "./usuarios.db",
  driver: sqlite3.Database
});

// Criar tabela de usuários se não existir
await db.exec(`
  CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    senhaHash TEXT
  )
`);

// Rota inicial
app.get("/", (req, res) => {
  res.send("Servidor rodando! Use /register para criar conta e /login para autenticar 🚀");
});

// Registro de usuário
app.post("/register", async (req, res) => {
  const { email, senha } = req.body;

  // verifica se já existe
  const usuarioExiste = await db.get("SELECT * FROM usuarios WHERE email = ?", [email]);
  if (usuarioExiste) {
    return res.status(400).json({ erro: "Usuário já registrado" });
  }

  // cria hash da senha
  const senhaHash = await bcrypt.hash(senha, 10);

  // salva no banco
  await db.run("INSERT INTO usuarios (email, senhaHash) VALUES (?, ?)", [email, senhaHash]);

  res.json({ mensagem: "Usuário registrado com sucesso!", usuario: { email } });
});

// Login
app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  const usuario = await db.get("SELECT * FROM usuarios WHERE email = ?", [email]);
  if (!usuario || !(await bcrypt.compare(senha, usuario.senhaHash))) {
    return res.status(401).json({ erro: "Credenciais inválidas" });
  }

  const token = jwt.sign({ id: usuario.id, email: usuario.email }, "segredo123", { expiresIn: "1h" });
  res.json({ token });
});

// Middleware de autenticação
function autenticar(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ erro: "Token não fornecido" });

  jwt.verify(token, "segredo123", (err, usuario) => {
    if (err) return res.status(403).json({ erro: "Token inválido" });
    req.usuario = usuario;
    next();
  });
}

// Rota protegida
app.get("/protegido", autenticar, (req, res) => {
  res.json({
    mensagem: "Você acessou a rota protegida!",
    usuario: req.usuario
  });
});

// Listar usuários (sem mostrar senha)
app.get("/usuarios", async (req, res) => {
  const todosUsuarios = await db.all("SELECT id, email FROM usuarios");
  res.json(todosUsuarios);
});

app.listen(3000, () => console.log("🚀 Servidor rodando em http://localhost:3000"));
