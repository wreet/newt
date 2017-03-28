var fs = require("fs");
var path = require('path');

var logging = {

  logEvent: function(log_dir, str) {
    // make sure we can write to the output dir
    str = "[" + Date.now() + "] " + str + "\n";
    try {
      var res = fs.appendFileSync(path.join(log_dir, "newt_log"), str);
    } catch (e) {
      console.log("logging error, must exit: " + e);
      process.exit();
    }
  }


};

module.exports = logging;
