var express = require('express');
var http = require('http');
var api_helper = require('./helpers/api_helper');
var app = express();


app.use(express.json());
app.use(express.urlencoded());
app.use(app.router);

app.set('port', process.env.PORT || 8081);

// development only
if ('development' == app.get('env')) {
  app.use(express.errorHandler());
}


app.post('/api/nodev1/users/login', function(req, res){

  var pk = req.headers['x-api-key'];
  var email = req.param('email', null);
  var password = req.param('password', null);

  api_helper.retrieve_pk(pk, function(sk)
  {
  	
  	// call login WS
  	api_helper.login(pk, sk, email, password, function(data){
  		var body = data;
		res.setHeader('Content-Type', 'text/plain');
		res.setHeader('Content-Length', body.length);
		res.end(body);
  	});
  });
});


app.post('/api/nodev1/hash/:url', function(req, res){
	var url_to_hash = req.param('url', null);
	var pk = req.headers['x-api-key'];
	var token = req.param('token', null);
	var email = req.param('email', null);
	
	api_helper.check_token(email, token, pk, function(data)
	{
	  	if (data.token_valid)
  		{
  			var digest = api_helper.generate_hmac(data.sk, url_to_hash);
  			var body = '{"digest" : '+ digest +'}';
  			res.setHeader('Content-Type', 'text/plain');
			res.setHeader('Content-Length', body.length);
			res.end(body);
  		}
  		else
  		{
  			var body = '{"error" : Invalid Token}';
  			res.setHeader('Content-Type', 'text/plain');
			res.setHeader('Content-Length', body.length);
			res.end(body);
  		}
	});
});



http.createServer(app).listen(app.get('port'), function(){
  console.log('Express server listening on port ' + app.get('port'));
});
