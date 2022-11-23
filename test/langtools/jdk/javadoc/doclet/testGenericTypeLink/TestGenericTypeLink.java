/*
 * Copyright (c) 2020, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/*
 * @test
 * @bug     8177280
 * @summary see and link tag syntax should allow generic types
 * @library ../lib
 * @modules jdk.javadoc/jdk.javadoc.internal.tool
 * @build JavadocTester
 * @run main TestGenericTypeLink
 */

public class TestGenericTypeLink extends JavadocTester {

    public static void main(String... args) throws Exception {
        TestGenericTypeLink test = new TestGenericTypeLink();
        test.runTests();
    }

    /**
     * Test valid internal and external links to generic types.
     */
    @Test
    public void testValidLinks() {
        javadoc("-d", "out1",
                "-sourcepath", testSrc,
                "-linkoffline", "http://example.com/docs/api/", testSrc,
                "-package", "pkg1");
        checkExit(Exit.OK);
        checkOutput("pkg1/A.html", true,
                "<div class=\"block\"><code><a href=\"http://example.com/docs/api/java.base"
                + "/java/util/List.html?is-external=true\" title=\"class or interface in java.util\" "
                + "class=\"externalLink\">List</a>&lt;<a href=\"http://example.com/docs/api/"
                + "java.base/java/lang/String.html?is-external=true\" title=\"class or interface in java.lang\" "
                + "class=\"externalLink\">String</a>&gt;</code>\n"
                + " <a href=\"http://example.com/docs/api/java.base/java/util/"
                + "List.html?is-external=true\" title=\"class or interface in java.util\" class=\"externalLink\">"
                + "List</a>&lt;? extends <a href=\"http://example.com/docs/api/java.base/"
                + "java/lang/CharSequence.html?is-external=true\" title=\"class or interface in java.lang\" "
                + "class=\"externalLink\">CharSequence</a>&gt;\n"
                + " <a href=\"#someMethod(java.util.List,int)\"><code>someMethod("
                + "ArrayList&lt;Integer&gt;, int)</code></a>\n"
                + " <a href=\"#otherMethod(java.util.Map,double)\"><code>otherMethod("
                + "Map&lt;String, StringBuilder&gt;, double)</code></a></div>\n",

                "<dl>\n"
                + "<dt><span class=\"seeLabel\">See Also:</span></dt>\n"
                + "<dd><code><a href=\"http://example.com/docs/api/java.base/"
                + "java/util/Map.html?is-external=true\" title=\"class or interface in java.util\" "
                + "class=\"externalLink\">Map</a>&lt;<a href=\"http://example.com/"
                + "docs/api/java.base/java/lang/String.html?is-external=true\" title=\"class or interface "
                + "in java.lang\" class=\"externalLink\">String</a>,&#8203;? extends "
                + "<a href=\"http://example.com/docs/api/java.base/"
                + "java/lang/CharSequence.html?is-external=true\" title=\"class or interface in "
                + "java.lang\" class=\"externalLink\">CharSequence</a>&gt;</code>, \n"
                + "<code><a href=\"http://example.com/docs/api/java.base/"
                + "java/util/Map.html?is-external=true\" title=\"class or interface in java.util\" "
                + "class=\"externalLink\">Map</a>&lt;<a href=\"http://example.com/docs/api/"
                + "java.base/java/lang/String.html?is-external=true\" title=\"class or interface in java.lang\" "
                + "class=\"externalLink\">String</a>,&#8203;? super <a href=\"A.html\" title=\"class in pkg1\">"
                + "A</a>&lt;<a href=\"http://example.com/docs/api/java.base/"
                + "java/lang/String.html?is-external=true\" title=\"class or interface in java.lang\" "
                + "class=\"externalLink\">String</a>,&#8203;? extends <a href=\"http://example.com/docs/api"
                + "/java.base/java/lang/RuntimeException.html?is-external=true\" "
                + "title=\"class or interface in java.lang\" class=\"externalLink\">RuntimeException</a>"
                + "&gt;&gt;</code>, \n"
                + "<a href=\"#someMethod(java.util.List,int)\"><code>someMethod"
                + "(List&lt;Number&gt;, int)</code></a>, \n"
                + "<a href=\"#otherMethod(java.util.Map,double)\"><code>otherMethod"
                + "(Map&lt;String, ? extends CharSequence&gt;, double)</code></a></dd>\n"
                + "</dl>"
                );
        checkOutput("pkg1/A.SomeException.html", true,
                "<div class=\"block\"><code><a href=\"A.html\" title=\"class in pkg1\">A</a>&lt;"
                + "<a href=\"http://example.com/docs/api/java.base/java/lang/String.html?is-external=true"
                + "\" title=\"class or interface in java.lang\" class=\"externalLink\">String</a>"
                + ",&#8203;<a href=\"A.SomeException.html\" title=\"class in pkg1\">A.SomeException</a>&gt;</code>\n"
                + " <a href=\"http://example.com/docs/api/java.base/java/util/Map.html?is-external=true"
                + "\" title=\"class or interface in java.util\" class=\"externalLink\">"
                + "link to generic type with label</a></div>",

                "<dl>\n"
                + "<dt><span class=\"seeLabel\">See Also:</span></dt>\n"
                + "<dd><code><a href=\"A.html\" title=\"class in pkg1\">A</a>&lt;<a href=\"http://example.com/docs/api"
                + "/java.base/java/lang/String.html?is-external=true\" "
                + "title=\"class or interface in java.lang\" class=\"externalLink\">String</a>"
                + ",&#8203;<a href=\"A.SomeException.html\" title=\"class in pkg1\">A.SomeException</a>&gt;</code>, \n"
                + "<a href=\"http://example.com/docs/api/java.base/"
                + "java/util/List.html?is-external=true\" title=\"class or interface in java.util\" "
                + "class=\"externalLink\"><code>Link to generic type with label</code></a></dd>\n"
                + "</dl>"
                );
    }

    /**
     * Test invalid links to generic types.
     */
    @Test
    public void testInvalidLinks() {
        javadoc("-d", "out2",
                "-sourcepath", testSrc,
                "-linkoffline", "http://example.com/docs/api/", testSrc,
                "-package", "pkg2");
        checkExit(Exit.ERROR);
        checkOutput("pkg2/B.html", true,
                "<div class=\"block\"><code>java.util.Foo<String></code>\n"
                + " Baz<Object>\n"
                + " <code>#b(List<Integer>)</code></div>",

                "<dl>\n"
                + "<dt><span class=\"seeLabel\">See Also:</span></dt>\n"
                + "<dd><code>java.util.List<Bar></code>, \n"
                + "<code>Baz<Object, String></code>, \n"
                + "<code>B#b(List<Baz>)</code></dd>\n</dl>");
    }
}
