import express from "express";

const app = express();

app.get("/run", (req, res) => {
    const userInput: string = req.query.cmd as string;

    const result = eval(userInput);

    res.send(String(result));
});