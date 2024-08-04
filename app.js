const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dns = require("dns");
const cors = require("cors");
const { ObjectId } = require("bson");
require("dotenv").config();

const { readDb, writeDb } = require("./utils");

const app = express();
app.use(express.json());
app.use(cors());

// Função para obter um novo ID
const getNewId = () => {
  return new ObjectId().toString();
};

// Open Route
app.get("/", (req, res) => {
  res.status(200).json({ message: "Bem vindo a api" });
});

// Middleware para checar o token
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Acesso negado" });
  }

  try {
    const secret = process.env.SECRET;
    if (!secret) {
      throw new Error("Secret key not set");
    }
    jwt.verify(token, secret);
    next();
  } catch (error) {
    res.status(400).json({ message: "Token inválido!" });
  }
}

// Rota para obter todos os registros de informática
app.get("/informatica", checkToken, async (req, res) => {
  try {
    const db = readDb();
    res.status(200).json(db.informaticaRecords);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Erro ao obter registros", error: error.message });
  }
});

// Rota para obter todos os registros de informática
app.get("/multidisciplinar", checkToken, async (req, res) => {
  try {
    const db = readDb();
    res.status(200).json(db.multidisciplinarRecords);
  } catch (error) {
    res
      .status(500)
      .json({ message: "Erro ao obter registros", error: error.message });
  }
});

// Rota para registrar um novo formulário de informática
app.post("/informatica/register", async (req, res) => {
  const {
    professor,
    email,
    data,
    modalidade,
    alunos,
    laboratorio,
    software,
    equipamento,
    observacao,
    token,
    userID,
  } = req.body;

  if (
    !professor ||
    !email ||
    !data ||
    !modalidade ||
    !alunos ||
    !laboratorio ||
    !software ||
    !equipamento ||
    !observacao ||
    !token
  ) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  try {
    const db = readDb();

    const registrosNoDia = db.informaticaRecords.filter(
      (record) => record.data === data
    ).length;

    if (registrosNoDia >= 5) {
      return res
        .status(400)
        .json({ message: "Laboratório Esgotado para esse dia" });
    }

    const laboratorioExistente = db.informaticaRecords.find(
      (record) => record.data === data && record.laboratorio === laboratorio
    );

    if (laboratorioExistente) {
      return res.status(400).json({
        message: "Laboratório já possui uma solicitação para esse dia",
      });
    }

    const informatica = {
      id: getNewId(),
      professor,
      email,
      data,
      modalidade,
      alunos,
      laboratorio,
      software,
      equipamento,
      observacao,
      token,
      userID,
      status: "Aguardando Confirmação", // Adiciona o status padrão
    };

    db.informaticaRecords.push(informatica);
    writeDb(db);

    res.status(201).json({ message: "Formulário registrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao registrar formulário" });
  }
});

const validDomains = ["kroton.com.br", "cogna.com.br"];

const isValidEmailFormat = (email) => {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
};

const isDomainValid = (domain) => {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (err, addresses) => {
      if (err || addresses.length === 0) {
        resolve(false);
      } else {
        resolve(true);
      }
    });
  });
};

app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  if (password !== confirmpassword) {
    return res.status(400).json({ message: "As senhas não conferem" });
  }

  if (!isValidEmailFormat(email)) {
    return res.status(400).json({ message: "Formato de email inválido" });
  }

  const emailDomain = email.split("@")[1];
  if (!validDomains.includes(emailDomain)) {
    return res.status(400).json({
      message:
        "Por favor, utilize um email institucional (@kroton.com.br ou @cogna.com.br)",
    });
  }

  const isDomainValidResult = await isDomainValid(emailDomain);
  if (!isDomainValidResult) {
    return res
      .status(400)
      .json({ message: "O domínio do email não possui registros válidos" });
  }

  const db = readDb();
  const userExists = db.users.find((user) => user.email === email);
  if (userExists) {
    return res.status(400).json({ message: "Email já cadastrado" });
  }

  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  const user = {
    id: getNewId(),
    name,
    email,
    password: passwordHash,
    role: "user",
  };

  db.users.push(user);
  writeDb(db);

  try {
    res.status(201).json({ message: "Usuário cadastrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao cadastrar" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  const db = readDb();
  const user = db.users.find((user) => user.email === email);

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado!" });
  }

  const checkPassword = await bcrypt.compare(password, user.password);
  if (!checkPassword) {
    return res.status(422).json({ message: "Senha incorreta" });
  }

  try {
    const secret = process.env.SECRET;
    if (!secret) {
      return res.status(500).json({ message: "Secret key not set" });
    }
    const token = jwt.sign({ id: user.id }, secret);
    res
      .status(200)
      .json({ message: "Logado com sucesso", token, userId: user.id });
  } catch (error) {
    res.status(500).json({ message: "Erro ao logar" });
  }
});

app.get("/auth/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  const db = readDb();
  const user = db.users.find((user) => user.id === id);

  if (!user) {
    return res.status(404).json({ message: "Usuário não encontrado" });
  }

  res.status(200).json({ user });
});

// Rota para registrar um novo formulário multidisciplinar
app.post("/multidisciplinar/register", async (req, res) => {
  const {
    professor,
    email,
    data,
    modalidade,
    alunos,
    laboratorio,
    curso,
    turno,
    semestre,
    disciplina,
    tema,
    roteiro,
    observacao,
    token,
    userID,
  } = req.body;

  if (
    !professor ||
    !email ||
    !data ||
    !modalidade ||
    !alunos ||
    !laboratorio ||
    !curso ||
    !turno ||
    !semestre ||
    !disciplina ||
    !tema ||
    !roteiro ||
    !observacao ||
    !token
  ) {
    return res.status(400).json({ message: "Preencha todos os campos" });
  }

  try {
    const db = readDb();

    const registrosNoDia = db.multidisciplinarRecords.filter(
      (record) => record.data === data
    ).length;

    if (registrosNoDia >= 5) {
      return res
        .status(400)
        .json({ message: "Laboratório Esgotado para esse dia" });
    }

    const laboratorioExistente = db.multidisciplinarRecords.find(
      (record) => record.data === data && record.laboratorio === laboratorio
    );

    if (laboratorioExistente) {
      return res.status(400).json({
        message: "Laboratório já possui uma solicitação para esse dia",
      });
    }

    const formulario = {
      id: getNewId(),
      professor,
      email,
      data,
      modalidade,
      alunos,
      laboratorio,
      curso,
      turno,
      semestre,
      disciplina,
      tema,
      roteiro,
      observacao,
      token,
      userID,
      status: "Aguardando Confirmação", // Adiciona o status padrão
    };

    db.multidisciplinarRecords.push(formulario);
    writeDb(db);

    res.status(201).json({ message: "Formulário registrado com sucesso" });
  } catch (error) {
    res.status(500).json({ message: "Erro ao registrar formulário" });
  }
});

/// Nova rota para buscar token específico
app.get("/buscartoken/:id", checkToken, async (req, res) => {
  const { id } = req.params;
  try {
    const db = readDb();

    if (!db || (!db.informaticaRecords && !db.multidisciplinarRecords)) {
      return res
        .status(500)
        .json({ message: "Erro ao carregar os dados do banco de dados" });
    }

    let record = null;

    // Verifica em informaticaRecords
    if (db.informaticaRecords) {
      record = db.informaticaRecords.find((record) => record.token === id);
    }

    // Verifica em multidisciplinarRecords se não encontrou ainda
    if (!record && db.multidisciplinarRecords) {
      record = db.multidisciplinarRecords.find((record) => record.token === id);
    }

    if (!record) {
      return res.status(404).json({ message: "Token não encontrado" });
    }

    res.status(200).json(record);
  } catch (error) {
    console.error("Erro ao obter dados do token:", error);
    res
      .status(500)
      .json({ message: "Erro ao obter dados do token", error: error.message });
  }
});

app.listen(80, () => {
  console.log("Servidor Ligado com sucesso.");
});
