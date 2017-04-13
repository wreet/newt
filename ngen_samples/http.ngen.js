/*
  METHOD /some/path/to/file HTTP/1.1
  Host: sample.wreet.co
  Authorization: token 0faded0faded
  Content-Type: application/whatever
  Accept-Encoding: gzip, deflate, br
*/

var ngen = require("./ngen");

ngen.enum(["GET", "POST", "HEAD", "DELETE", "OPTIONS"]);
ngen.literal(" /");
ngen.junk({len: 10, variance: 10});
ngen.literal(" HTTP/1.");
ngen.byte();
ngen.literal("\r\n");
ngen.literal("Host: ");
ngen.junk({len: 16, variance: 64});
ngen.literal(".com");
ngen.literal("\r\n");
ngen.literal("Authorization: token ");
ngen.junk({len: 12, variance: 5});
ngen.literal("\r\n");
ngen.literal("Content-type: ");
ngen.junk({len: 8, variance: 10});
ngen.literal("/");
ngen.junk({len: 5, variance: 20});
ngen.literal("\r\n");
ngen.literal("Accept-Encoding: ");
ngen.junk({len: 4, variance: 10});
ngen.literal(", ");
ngen.junk({len: 4, variance: 10});

console.log(ngen.buff);
