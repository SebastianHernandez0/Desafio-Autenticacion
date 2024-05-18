const express = require("express");
const cors = require("cors");
const port = process.env.PORT ?? 3000;
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const app = express();
const key = "secret";
const key2= "secret2";
const {Pool} = require('pg');
require('dotenv').config();


const pool = new Pool({
    user: 'postgres',
    host: 'localhost',
    database: 'softjobs',
    password: process.env.PASSWORD,
    port: 5432,
    allowExitOnIdleConnection: true,
});


const verifyToken = (req, res, next) => {
    const Vtoken = req.headers.authorization;
    if (!Vtoken) {
      return res.status(401).json({ message: "No token provided" });
    }
    const [bearer, token] = Vtoken.split(" ");

    if(bearer!== "Bearer") {
        return res.status(401).json({ message: "Invalid token" });
    }
    try {
        jwt.verify(token, key) && next();



    } catch (error) {
        res.status(401).json({ message: "Invalid token!!" });
    }
  };
app.use(cors());
app.use(express.json());

app.post("/usuarios", async (req, res) => {
  try {
    const { email, password, rol, lenguage } = req.body;
    const consulta =
      "INSERT INTO usuarios (id,email,password,rol,lenguage) VALUES (DEFAULT,$1,$2,$3,$4) RETURNING *;";
    const values = [email, bcrypt.hashSync(password), rol, lenguage];
    const { rows } = await pool.query(consulta, values);
    res.status(201).json({
      id: rows[0].id,
      email: rows[0].email,
    });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const consulta = "SELECT * FROM usuarios WHERE email=$1";
    const values = [email];
    const { rows } = await pool.query(consulta, values);
    if (rows.length === 0) {
      return res
        .status(404)
        .json({ message: "Usuario no encontrado", code: 404 });
    }
    const user = rows[0];
    const verifiedUser = bcrypt.compareSync(password, user.password);
    if (!verifiedUser) {
      return res
        .status(401)
        .json({ message: "Contraseña incorrecta", code: 401 });
    }
    
    const token = jwt.sign(
      {
        email: user.email,
        rol: user.rol,
        password: user.password,
        lenguage: user.lenguage,
      },key
    );
    res.status(200).json({ message: "token", token });
  } catch (error) {
    res.status(500).send(error.message);
  }
});

app.get("/usuarios",verifyToken, async (req, res) => {
    try {
      const authorization = req.headers.authorization.split(" ");
      const token = authorization[1];
      const query = "SELECT * FROM usuarios WHERE email= $1;";
      const {email} = jwt.verify(token, key);
      const {rows} = await pool.query(query, [email]);
      const user = rows[0];

      if(!user){
        return res.status(404).json({message: "Usuario no encontrado", code: 404});
      }if(user){
        res.status(200).json([user]);
      }
    } catch (error) {
      res.status(500).send(error.message);
    }
})

app.listen(port, console.log(`Listening on port ${port}`));
