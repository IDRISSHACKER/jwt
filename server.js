const express = require('express');
const bodyParser = require("body-parser");
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const APP_PORT = process.env.PORT || 4000;

app.use(bodyParser.json());
app.use(cors());

const user = {
    id: 42,
    name: "IDRISS HACKER",
    email: "idrisscoder@gmail.com",
    password: "123456",
    admin: true
}

const generateAcessToken = (user) => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: "60s"})
}

const generateRefreshToken = (user) => {
    return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: "120s" })
}

app.post("/api/login", (req, res) => {
    if (req.body.email != user.email || req.body.password != user.password){
        res.status(401).send("Invalid credentials");
        return;
    }

    const userToken = generateAcessToken(user)
    const refreshToken = generateRefreshToken(user)
    res.status(200).json({
        userToken,
        refreshToken
    })

})

app.post("/api/refreshToken", (req, res)=>{
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.sendStatus(401)
    }

    jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403)
        }

        delete user.iat;
        delete user.exp;
        const regeneratedToken = generateAcessToken(user)
        res.status(200).json({
            userToken: regeneratedToken
        })
    })

})

const authToken = (req, res, next) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.sendStatus(401)
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403)
        }

        req.user = user
        next()
    })

}

app.get("/api/me", authToken, (req, res) => {
    res.status(200).json(req.user)
})

app.listen(APP_PORT, () => {
    console.log(`Server is listening on port ${APP_PORT}`)
})