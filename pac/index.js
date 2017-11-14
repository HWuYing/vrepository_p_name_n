const express = require('express');
const path = require('path');
const app = express();

const {PAC_PORT} = require("./../config");

app.use(express.static(path.join(__dirname, 'public')));


app.use(express.urlencoded({extended: true}));


app.use(function (req, res, next) {
	res.writeHead(200,{'Content-Type':'text/html;charset=utf-8'});
	next();
});

app.get('/',(req,res) => {
	res.write('pac服务器');
	res.end();
});

app.use(function (err, req, res, next) {
	res.status(500);
	res.write(`服务器内部错误:\n${err.message}`);
	res.end();
});

app.use(function (req, res, next) {
	res.status(404);
	res.write(`没有找到资源`);
	res.end();
});

app.listen(PAC_PORT);
console.log(`Express started on port ${PAC_PORT}`);
