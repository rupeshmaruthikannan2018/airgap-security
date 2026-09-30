const express = require('express');
const app = express();
app.get('/run', (req, res) => {
    const userInput = req.query.cmd;
    const result = eval(userInput);
    res.send(String(result));
});
