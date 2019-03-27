#!/usr/bin/env node

/*                                                                                                                                                                               
  * newt.js, a simple node-powered fuzzer by @chaseahiggins                                                                                                                      
  *****************************************************************************                                                                                                  
  * newt provides a simple, extensible method to perform file format fuzzing                                                                                                     
  * by exposing various function hooks to set the monitoring and fuzz methods                                                                                                    
  * newt makes it easy to add custom process monitoring/exit handling and                                                                                                        
  * can easily be modified to accept more fuzzing methods.                                                                                                                       
  *****************************************************************************                                                                                                  
  * BUGS/TODO:                                                                                                                                                                   
    * the new standalone procmon reveals how tangled a mess things are, needs to be fixed fast <---||||f                                                                     
    * unite arg parsers                                                                                                        
    * eliminate dependence on exploitable module in gdb mode (or coopt gdb.js into this codebase)                                                                                  
    * move crash logging deal to logging class                                                                                                                                     
    * new fuzz modes:                                                                                                                                                              
    *   rotate fuzz where we bitwise rotate a selection of byte(s)                                                                                                     
    * add support for fuzzing cli args                                                                                                                                       
    * add support for fuzzing via stdin                                                                                                                                            
    * that master result obj needs to be consistent                                                                           
    * port newt to windows including windbg monitor mode                                                                                                                     
    * autofuzz mode should should switch to exit code + message with next()                                                                                                  
    * cache ngen files in memory to reduce tight file reads     
    * netfuzzing mode is not complete
    * add crash minimizer                                                                                                                   
    * some tests would be nice yeah?                                                                                                                                               
  *****************************************************************************                                                                                                  
 */

var fs = require('fs');

var newt = newt || {};
// our shit                                                                                                                                                                      
newt.procmon = require('./lib/procmon');
newt.fuzzing = require('./lib/fuzzing');
newt.fuzzer = require('./lib/fuzz_director');

// options
newt.opts = {
  debug: 1
};

// cli interpretron time
if (require.main === module) {
  // we will keep cli stuff real simple, check first arg, exec accordingly
  switch (process.argv[2]) {
    case "randbuff": // random buffer
      // print a random buffer of argv[3] len
      if (process.argv.length < 5) {
        console.log("Generate a random string of a provided length:");
        console.log("\tuse: newt.js randbuff -l <str len>");
        console.log("\tex: newt.js randbuff -l 32");
        process.exit();
      }
      var args = process.argv.slice(3);
      for (var i = 0; i < args.length; i++) {
        var arg = args[i];
        switch (arg) {
          case "-l": // str length
            args.str_len = args[++i];
            break;
        }
      }
      var b = newt.fuzzing.randBuff(args.str_len, {
        printable_only: 1
      });
      process.stdout.write(b);
      break;

    case "mutate": // mangle buffer
      if (process.argv.length < 5) {
        console.log("Take buffer from stdin, mangle every fuzz factor bytes and print to stdout:");
        console.log("\tuse: newt.js mutate -f <fuzz factor>");
        console.log("\tex: cat seed.jpg | ./newt.js mutate -f 32 -x ripple > case.jpg");
        console.log("\tavailable mutators are: buffmangler, bitflip, byteflip, bytearith, chunkspew, ripple");
        process.exit();
      }
      var args = newt.fuzzer.utils.parseArgs(process.argv.slice(3));
      // take a stdinput, mangle it to stdout
      if (!args.mutators) {
        console.log("[!] mutatation mode requires you to set a mutator with flag -x (e.g. -x ripple");
        console.log("[i] try \"newt.js mutate\" for more information");
        process.exit();
      }
      process.stdin.resume();
      process.stdin.setEncoding('utf8');
      process.stdin.on('data', function (buff) {
        var b = newt.fuzzing[args.mutators[0].name](buff, {
          fuzz_factor: args.fuzz_factor
        });
        process.stdout.write(b);
      });
      break;

    case "autofuzz": // go through and fuzz a subject automagically
      if (process.argv.length < 9) {
        console.log("Perform an unattended fuzz run on a subject binary");
        console.log("\tuse: newt.js autofuzz -s <subject> -i <seeds_sir> -o <output_dir> [-k <kill_time> -m <monitor_mode> -f <fuzz_factor> -x <mutators>]");
        console.log("\tex: newt.js autofuzz -f 32 -s okular -m gdb -i seeds -o out -k 2");
        console.log("\tavailable monitoring modes are: gdb, asan");
        console.log("\tavailable mutators are: buffmangler, bitflip, byteflip, bytearith, chunkspew, ripple");
        console.log("\tfuzz factor roughly translates to fuzzing 1/-f bytes");
        process.exit();
      }
      var opts = newt.fuzzer.utils.parseArgs(process.argv.slice(3));
      newt.fuzzer.autoFuzz(opts);
      break;

    case "netfuzz": // much like autofuzz, but assuming the local instance unable to procmon
      /*
        * for now, we will just use sockets I guess, and assume that the ngen file
        * has taken care of the hard work of describing the correct protocol
        */      
      if (process.argv.length < 9) {
        console.log("Fuzz a remote network service");
        console.log("\tuse newt.js netfuzz -i <ngen_seeds_dir> -o <logging_dir> -h <host:port>");
        console.log("\tex: newt.js netfuzz -i ngen_seeds -o out -h localhost:1337");
        console.log("\tnote: ngen seed exmaples come with newt, will be further documented in the future");
        process.exit();
      }
      var args = process.argv.slice(3);
      for (var i = 0; i < args.length; i++) {
        var arg = args[i];
        switch (arg) {
          case "-h":
            // set the host:port
            args.host = args[++i];
            break;
          case "-o":
            // out dir
            args.out_dir = args[++i];
            break;
          case "-i":
            // seeds dir
            args.seeds_dir = args[++i];
            break;
        }
      } // end options iteration
      newt.fuzzer.netFuzz(args);
      break; // end netfuzz

    case "procmon": // simply spawn a proc to mon, fuzzing will happen elsewhere
      // parse args from stdin
      if (process.argv.length < 7) {
        console.log("Spawn a process with arguments and monitor for crashes");
        console.log("\tuse: ./newt.js procmon -s <subject bin + args> -m <monitor mode>");
        console.log("\tex: ./newt.js procmon -s firefox case.html -m asan");
        console.log("\tavailable monitoring modes are gdb, asan, none");
        process.exit();
      }
      var args = process.argv.slice(3);
      for (var i = 0; i < args.length; i++) {
        var arg = args[i];
        switch (arg) {
          case "-r":
            // respawn proc if crashes
            args.respawn = true;
            continue;

          case "-o":
            // output directory
            args.out_dir = args[++i];
            continue;

          case "-s":
            // the fuzz subject
            // special case where we may need to collect multiple
            var cmd = [];
            while (args[++i] && args[i].indexOf("-") !== 0 && i < args.length) // find all opts
              cmd.push(args[i]); // append to the cmd arr
            // now set it all
            args.subject = cmd;
            i -= 1;
            continue;

          case "-m":
            // monitor mode, default gdb
            args.monitoring = {
                mode: args[++i],
                launcher: null
            };
            continue;

            default:
              console.log("[-] Unrecognized option: " + arg);
        } // end switch
      } // end for
      newt.procmon.standaloneMonitor(args, null);
      break;

    default:
      // help case
      console.log("[~] newt.js " + require('./package.json').version + " - a simple node-powered fuzzer");
      console.log("Usage: newt command [opts]");
      console.log("Specify any command with no options for more usage information\n");
      console.log("Commands:");
      // autofuzz
      console.log("  autofuzz    Automatically generate cases and fuzz the subject");
      console.log("  |  -i       Required, directory where file format or ngen seeds can be found");
      console.log("  |  -o       Required, output directory for crashes, logs, cases");
      console.log("  |  -s       Required, the subject binary to fuzz");
      console.log("  |  -k       Optional, kill subject after -k seconds, useful for GUI bins");
      console.log("  |  -f       Optional, int value that translates to fuzzing 1/-f byte in most mutators");
      console.log("  |  -m       Optional, monitor mode. Default is gdb, asan instrumented bins also supported");
      console.log("  |  -x       Optional, comma-separated list of mutators(e.g. ripple,chunkspew) default is all");
      console.log(); // newline
      // procmon
      console.log("  procmon     Launch and monitor a process");
      console.log("  |  -s       Required, the subject binary [with args]");
      console.log("  |  -m       Required, monitor mode [asan|gdb]");
      console.log("  |  -r       Optional, respawn process on exit(flag takes no args)");
      console.log("  |  -o       Optional, output dir. Results printed to console if none specified");
      console.log();
      // netfuzz
      console.log("  netfuzz     Fuzz a remote network service");
      console.log("  |  -i       Required, directory where ngen seeds can be found");
      console.log("  |  -o       Required, output directory for crashes, logs, cases");
      console.log("  |  -h       Required, the host to send the fuzz case as host:port");
      console.log();
      // randbuff
      console.log("  randbuff    Generate a random string for use elsewhere");
      console.log("  |  -l       Required, length of string to generate");
      console.log();
      // mutate
      console.log("  mutate      Mutate an input buffer from stdin, write it to stdout");
      console.log("  |  -f       Required, fuzz factor for the input buffer");
      console.log("  |  -x       Required, the mutator to use(e.g. ripple)");
  } // end comm switch
} // end arg handling