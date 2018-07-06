/*
<?xml version="1.0" encoding="UTF-8" ?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1">
  <rect x="25" y="25" width="200" height="200" fill="lime" stroke-width="4" stroke="pink" />
  <circle cx="125" cy="125" r="75" fill="orange" />
  <polyline points="50,150 50,200 200,200 200,100" stroke="red" stroke-width="4" fill="none" />
  <line x1="50" y1="50" x2="200" y2="200" stroke="blue" stroke-width="4" />
</svg>
*/

var ngen = require("../lib/ngen"); // include for debug from console

ngen.literal("<?xml version=\"");
ngen.enum(["1.0", "1.1"]);
ngen.literal("\" encoding=\"UTF-8\" ?>\n");
ngen.literal("<svg xmlns=\"http://wwww.w3.org/2000/svg\" version=\"1.1\">\n");
ngen.literal("<rect x=\"");
ngen.int({bits: 16});
ngen.literal("\" y=\"");
ngen.int({bits: 16});
ngen.literal("\" width=\"");
ngen.int({bits: 16});
ngen.literal("\" height=\"");
ngen.int({bits: 16});
ngen.literal("\" fill=\"lime\" stroke-width=\"");
ngen.int({bits: 16});
ngen.literal("\" stroke=\"pink\" />\n");
ngen.literal("<circle cx=\"");
ngen.int({bits: 16});
ngen.literal("\" cy=\"");
ngen.int({bits: 16});
ngen.literal("\" r=\"");
ngen.int({bits: 16});
ngen.literal("\" fill=\"orange\" />\n");
ngen.literal("<polyline points=\"");
ngen.int({bits: 16})
ngen.literal(",");
ngen.int({bits: 16})
ngen.literal(",");
ngen.int({bits: 16})
ngen.literal(",");
ngen.int({bits: 16})
ngen.literal(",");
ngen.int({bits: 16})
ngen.literal(",");
ngen.int({bits: 16}) 
ngen.literal(",");
ngen.int({bits: 16})
ngen.literal(",");
ngen.int({bits: 16})
ngen.literal("\" stroke=\"red\" stroke-width=\"");
ngen.int({bits: 16});
ngen.literal("\" fill=\"none\" />\n");
ngen.literal("<line x1=\"");
ngen.int({bits: 16});
ngen.literal("\" y1=\"");
ngen.int({bits: 16});
ngen.literal("\" x2=\"");
ngen.int({bits: 16});
ngen.literal("\" y2=\"");
ngen.int({bits: 16});
ngen.literal("\" stroke=\"blue\" stroke-width=\"");
ngen.int({bits: 16});
ngen.literal("\" />\n");
ngen.literal("</svg>");

console.log(ngen.buff); // include for debug from console
