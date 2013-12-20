var mysql  = require('mysql');
var yaml = require('js-yaml');
var fs   = require('fs');
var request = require('request')
var crypto = require('crypto');

var db_credentials = yaml.safeLoad(fs.readFileSync('./helpers/db.yml', 'utf8'));
var server_path = yaml.safeLoad(fs.readFileSync('./helpers/api_location.yml', 'utf8'));

var pool  = mysql.createPool({
  host     : db_credentials.host,
  user     : db_credentials.user,
  password : db_credentials.password,
  database : db_credentials.database
});


function retrieve_pk(public_key, callback){
	pool.getConnection(function(err, connection) {
	  // connected! (unless `err` is set)
	  var sql = "SELECT secret_api_key from api_licenses where public_api_key=" +  pool.escape(public_key) +" limit 1"
	  console.log(sql);

	  connection.query(sql, function(err, rows, fields) {
		  if (err) throw err;

		  console.log('The solution is: ', rows[0].secret_api_key);
		  connection.release();
		  callback(rows[0].secret_api_key);
		});
	});
}

function check_token(email, token, pk, callback){
	pool.getConnection(function(err, connection) {
	  // connected! (unless `err` is set)
	  var sql = "SELECT session_token from users where email =" +  pool.escape(email) 
	  

	  connection.query(sql, function(err, rows, fields) {
		  if (err) throw err;
		  connection.release();
		  
		  retrieve_pk(pk, function(sk){
		  	callback({ token_valid: rows[0].session_token == token, sk: sk});
		  })

		  
		});
	});
}

function generate_hmac(sk, text){
	var hmac = crypto.createHmac('sha1', sk);
	return hmac.update(text).digest('base64');
}

function login(pk, sk, email, password, callback){
	var login_method = server_path.method + "://" ;
	var login_url =  server_path.endpoint + server_path.loginws;
	
	// Generate the hmac
	var digest = generate_hmac(sk, login_method + login_url);

	request.post({
	  headers: {'X-API-KEY' : pk, 'X-URL-HASH': digest},
	  url:     login_method + login_url,
	  body:    "email="+email + "&password=" + password
	}, function(error, response, body){
	  console.log(body);
	  callback(body);
	});
}

exports.retrieve_pk = retrieve_pk;
exports.login = login;
exports.check_token = check_token;
exports.generate_hmac = generate_hmac;