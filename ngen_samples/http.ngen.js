/*
  METHOD /some/path/to/file HTTP/1.1
  Host: sample.wreet.co
  Authorization: token 0faded0faded
  Content-Type: application/whatever
  Accept-Encoding: gzip, deflate, br
*/

var ngen = require("../lib/ngen");

ngen.enum(["GET", "POST", "HEAD", "DELETE", "OPTIONS"]);
ngen.literal(" /");
ngen.junk({min_len: 10, max_len: 256});
ngen.literal(" HTTP/1.");
ngen.byte();
ngen.literal("\r\n");
ngen.literal("Host: ");
ngen.junk({min_len: 16, max_len: 256});
ngen.literal(".com");
ngen.literal("\r\n");
ngen.literal("Authorization: token ");
ngen.junk({min_len: 12, max_len: 32});
ngen.literal("\r\n");
ngen.literal("Content-type: ");
ngen.junk({len: 1});
ngen.literal("/");
ngen.junk({min_len: 3, max_len: 10});
ngen.literal("\r\n");
ngen.literal("Accept-Encoding: ");
ngen.junk({min_len: 4, max_len: 10});
ngen.literal(", ");
ngen.junk({min_len: 4, max_len: 10});

console.log(ngen.buff);
