const mongoose = require("mongoose");

// Define o esquema para o formulário de informática
const InformaticaSchema = new mongoose.Schema({
  professor: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  data: {
    type: Date,
    required: true,
  },
  modalidade: {
    type: String,
    required: true,
  },
  alunos: {
    type: Number,
    required: true,
  },
  laboratorio: {
    type: String,
    required: true,
  },
  software: {
    type: String,
    required: true,
  },
  equipamento: {
    type: String,
    required: true,
  },
  observacao: {
    type: String,
    required: true,
  },
  token: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    required: true,
    default: "Não",
  },
  userID: { type: String, required: true },
});

// Cria o modelo Informatica
const Informatica = mongoose.model("Informatica", InformaticaSchema);

module.exports = Informatica;
