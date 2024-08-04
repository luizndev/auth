const fs = require("fs");
const path = require("path");

const dbFilePath = path.join(__dirname, "db.json");

// Leitura do arquivo JSON
const readDb = () => {
  const rawData = fs.readFileSync(dbFilePath);
  return JSON.parse(rawData);
};

// Escrita no arquivo JSON
const writeDb = (data) => {
  const jsonData = JSON.stringify(data, null, 2);
  fs.writeFileSync(dbFilePath, jsonData);
};

module.exports = {
  readDb,
  writeDb,
};
