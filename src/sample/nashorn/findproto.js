/*
 * Copyright (c) 2015, Oracle and/or its affiliates. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Oracle nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// __proto__ magic property is non-standard. Use Object.getPrototypeOf
// and Object.setPrototypeOf instead. This script finds __proto__
// usage in scripts a given directory (recursively). If no directory 
// is specified the current working directory is scanned for scripts.

if (arguments.length == 0) {
    arguments[0] = ".";
}

var File = Java.type("java.io.File");
var file = new File(arguments[0]);
if (!file.exists()) {
    print(arguments[0] + " is neither a file nor a directory");
    exit(1);
}

var Files = Java.type("java.nio.file.Files");
var Parser = Java.type("jdk.nashorn.api.tree.Parser");
var SimpleTreeVisitor = Java.type("jdk.nashorn.api.tree.SimpleTreeVisitorES5_1");

var parser = Parser.create("-scripting", "--const-as-var");
var protoFound = false;

function checkFile(file) {
    // print("checking " + file);
    var ast = parser.parse(file, print);
    if (!ast) {
        return;
    }

    // locate __proto__ usage and warn
    ast.accept(visitor = new (Java.extend(SimpleTreeVisitor)) {
        lineMap: null,

        printWarning: function(node) {
            var pos = node.startPosition;
            var line = this.lineMap.getLineNumber(pos);
            var column = this.lineMap.getColumnNumber(pos);
            print("WARNING: __proto__ usage in " + file + " @ " + line + ":" + column);
        },

        checkProto: function(node, name) {
            if (name == "__proto__") {
                protoFound = true;
                this.printWarning(node);
            }
        },

        visitCompilationUnit: function(node, extra) {
            this.lineMap = node.lineMap;
            Java.super(visitor).visitCompilationUnit(node, extra);
        },

        visitIdentifier: function(node, extra) {
            this.checkProto(node, node.name);
            Java.super(visitor).visitIdentifier(node, extra);
        },

        visitMemberSelect: function(node, extra) {
            this.checkProto(node, node.identifier);
            Java.super(visitor).visitMemberSelect(node, extra);
        },

        visitProperty: function(node, extra) {
            this.checkProto(node, node.key);
            Java.super(visitor).visitProperty(node, extra);
        }
    }, null);
}

if (file.isDirectory()) {
    Files.walk(file.toPath())
        .filter(function(p) Files.isRegularFile(p))
        .filter(function(p) p.toFile().name.endsWith('.js'))
        .forEach(checkFile);
} else {
    checkFile(file);
}

if (protoFound) {
    print("__proto__ is non-standard. Use Object.get/setPrototypeOf instead");
}
