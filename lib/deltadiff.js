var fs = require("fs");
var cp = require("child_process");

var deltadiff = {
  diffs: [],

  cmpFiles: function(a, b, cb) { // our convention will be crash case at a, seed at b
    var child = cp.spawn("cmp", ["-l", a, b]);
    child.stdout.on("data", function(data) {
      var lines = data.toString().split("\n");
      for (line of lines) {
        line = line.trim();
        var parts = line.split(/\s+/);
        deltadiff.diffs.push({
          offset: parseInt(parts[0]),
          abyte: parseInt(parts[1]),
          bbyte: parseInt(parts[2])
        });
      }
      if (cb) cb(deltadiff.diffs);
    });
  } // end cmpFiles


}; 
// end deltadiff

deltadiff.cmpFiles("libqt5_qtextengineitemize.pdf", "docs.oracle_cheat.pdf", function(d) {
  console.log(d);

});