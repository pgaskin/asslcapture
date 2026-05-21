// SPDX-FileCopyrightText: 2026 Patrick Gaskin
// SPDX-License-Identifier: GPL-3.0-or-later

import javax.net.ssl.*;
import java.io.*;
import java.lang.reflect.Proxy;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

// javac --release 8 SSLClient.java
// $ANDROID_HOME/build-tools/36.0.0/d8 --output . --min-api 21 SSLClient.class
// adb push classes.dex /data/local/tmp/sslclient.dex
// adb shell CLASSPATH=/data/local/tmp/sslclient.dex app_process / SSLClient TLSv1.2 example.com 443
// adb shell CLASSPATH=/data/local/tmp/sslclient.dex app_process / SSLClient TLSv1.3 example.com 443

public class SSLClient {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("usage: SSLClient <tls-version> <hostname> <port>");
            System.exit(2);
        }
        String tlsVersion = args[0];
        String hostname = args[1];
        int port = Integer.parseInt(args[2]);

        X509TrustManager trustAll = (X509TrustManager) Proxy.newProxyInstance(
            X509TrustManager.class.getClassLoader(),
            new Class[]{X509TrustManager.class},
            (proxy, method, methodArgs) -> {
                switch (method.getName()) {
                    case "checkClientTrusted":
                    case "checkServerTrusted":
                        return null;
                    case "getAcceptedIssuers":
                        return new X509Certificate[0];
                    default:
                        throw new UnsupportedOperationException(method.getName());
                }
            }
        );

        SSLContext ctx = SSLContext.getInstance(tlsVersion);
        ctx.init(null, new TrustManager[]{trustAll}, new SecureRandom());

        try (BufferedReader maps = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = maps.readLine()) != null) {
                if (line.contains("libssl.so")) {
                    System.err.println(line.substring(line.lastIndexOf(' ') + 1));
                    break;
                }
            }
        }

        SSLSocket socket = (SSLSocket) ctx.getSocketFactory().createSocket(hostname, port);
        socket.setEnabledProtocols(new String[]{tlsVersion});
        socket.startHandshake();

        PrintWriter out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()));
        out.print("GET / HTTP/1.0\r\nHost: " + hostname + "\r\nConnection: close\r\n\r\n");
        out.flush();

        try (InputStream in = socket.getInputStream()) {
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                System.out.write(buf, 0, n);
            }
        }
    }
}
