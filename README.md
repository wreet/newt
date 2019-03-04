# newt.js

An easy to use, full-featured fuzzer designed for extensibility

## usage
```
Usage: newt command [opts]

Commands:
  autofuzz    Automatically generate cases and fuzz the subject
  |  -i       Required, directory where file format or ngen seeds can be found
  |  -o       Required, output directory for crashes, logs, cases
  |  -s       Required, the subject binary to fuzz
  |  -k       Sometimes required, kill subject after -k seconds, useful for GUI bins
  |  -f       Optional, int value that translates to fuzzing 1/-f byte in buffMangler mode
  |  -m       Optional, monitor mode. Default is gdb, asan instrumented bins also supported

  procmon     Launch and monitor a process
  |  -s       Required, the subject binary [with args]
  |  -m       Required, monitor mode [asan|gdb]
  |  -r       Optional, respawn process on exit
  |  -o       Optional, output dir. Results printed to console if none specified

  netfuzz     Fuzz a remote network service
  |  -o       Required, output directory for crashes, logs, cases
  |  -h       Required, the host to send the fuzz case as host:port

```

## features
newt.js does quite a lot - it can start and run through test cases completely unattended with two built-in monitoring modes: gdb or asan. It has several built-in mutators, all of which can accept an options array for tweaking. It's designed with extensibility in mind - you can easily hang whatever function you want on almost any method utilized by the fuzzer, allowing it to adapt to new monitoring modes or mutators with minimal hassle.

## examples
add some

A quick tutorial on usage can be found [on my blog](https://wreet.xyz/2018/03/04/simple-fuzzing-with-newt/).
