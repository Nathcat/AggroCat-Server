package com.nathcat.aggrocat_server;

import com.nathcat.RSA.EncryptedObject;
import com.nathcat.RSA.KeyPair;
import com.nathcat.RSA.PrivateKeyException;
import com.nathcat.RSA.RSA;
import com.sun.net.httpserver.*;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import java.io.*;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.concurrent.Executors;

public class Server {
    public static final String CIPHER_STRING = "AggroCat";
    public static final String PATH_CURRENT = "Assets/Data/current.map";
    public static final String PATH_KEY = "Assets/Data/key.catkey";

    private static boolean usingSSL = true;
    private static boolean bypassKey = false;
    private HashMap<Integer, Integer> current;
    private KeyPair keyPair;

    /**
     * Get the server's configuration file located at Assets/Server_Config.json
     * @return A JSONObject with the files contents
     * @throws FileNotFoundException Thrown if the config file does not exist
     * @throws ParseException Thrown if the config file contains a JSON syntax error
     */
    public static JSONObject getConfigFile() throws FileNotFoundException, ParseException {
        Scanner f = new Scanner(new File("Assets/Server_Config.json"));
        StringBuilder sb = new StringBuilder();
        while (f.hasNextLine()) {
            sb.append(f.nextLine());
        }

        return (JSONObject) new JSONParser().parse(sb.toString());
    }

    public static void main(String[] args) throws Exception {
        Server s = new Server(args);
    }

    public Server(String[] args) throws Exception {
        if (Arrays.stream(args).anyMatch("no-ssl"::equals)) {
            usingSSL = false;
        }

        if (Arrays.stream(args).anyMatch("bypass-key"::equals)) {
            bypassKey = true;
        }

        JSONObject config = null;
        try {
            config = getConfigFile();
        } catch (FileNotFoundException e) {
            System.err.println("Config file not found! Please make sure the config file exists at Assets/Server_Config.json!");
            System.exit(-1);
        } catch (ParseException e) {
            System.err.println("Syntax error in config file! Please check your JSON.");
            System.exit(-2);
        }

        assert config != null;

        if (config.get("port") == null) {
            System.err.println("Missing one or more fields in the config file, please ensure it includes \"php_exec_path\" and \"port\" fields.");
            System.exit(-3);
        }

        HttpServer server;
        if (usingSSL) {
            server = HttpsServer.create(new InetSocketAddress(Math.toIntExact((long) config.get("port"))), 0);
            JSONObject sslConfig = (JSONObject) new JSONParser().parse(new String(new FileInputStream("Assets/SSL_Config.json").readAllBytes()));
            LetsEncryptProvider provider = new LetsEncryptProvider(sslConfig);
            SSLContext sslContext = provider.getContext();
            ((HttpsServer) server).setHttpsConfigurator(new HttpsConfigurator(sslContext) {
                public void configure(HttpsParameters params) {
                    try {
                        JSONObject sslConfig = (JSONObject) new JSONParser().parse(new String(new FileInputStream("Assets/SSL_Config.json").readAllBytes()));
                        LetsEncryptProvider provider = new LetsEncryptProvider(sslConfig);
                        SSLContext context = provider.getContext();
                        SSLEngine engine = context.createSSLEngine();
                        params.setNeedClientAuth(false);
                        params.setCipherSuites(engine.getEnabledCipherSuites());
                        params.setProtocols(engine.getEnabledProtocols());
                        SSLParameters p = context.getSupportedSSLParameters();
                        params.setSSLParameters(p);
                    } catch (Exception e) {
                        System.err.println("Failed to create HTTPS port.");
                    }
                }
            });
        }
        else {
            server = HttpServer.create(new InetSocketAddress(Math.toIntExact((long) config.get("port"))), 0);
        }

        server.createContext("/GetCurrent", new GetCurrent());
        server.createContext("/AddPoint", new AddPoint());
        server.setExecutor(Executors.newCachedThreadPool());


        // Initialise data
        current = readCurrent();

        try {
            keyPair = readKey(PATH_KEY);
        }
        catch (FileNotFoundException e) {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(PATH_KEY));
            keyPair = RSA.GenerateRSAKeyPair();
            oos.writeObject(keyPair);
            oos.flush();
            oos.close();
        }

        System.out.println("Ready to accept HTTP" + (usingSSL ? "S" : "") + " connections on port " + config.get("port"));
        server.start();
    }

    /**
     * Transform a URI query string into a map of parameters to values.
     * @param query The query string
     * @return A map of parameter names to their values within the query string.
     */
    public static Map<String, String> queryToMap(String query) {
        Map<String, String> res = new HashMap<>();

        for (String s : query.split("&")) {
            String[] pv = s.split("=");
            if (pv.length > 1) {
                res.put(pv[0], pv[1]);
            }
            else {
                res.put(pv[0], "");
            }
        }

        return res;
    }

    public static void write(String path, HashMap<Integer, Integer> m) {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(path));
            oos.writeObject(m);
            oos.flush();
            oos.close();
        }
        catch (IOException ignored) {}
    }

    public static HashMap<Integer, Integer> read(String path) throws IOException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
        HashMap<Integer, Integer> m;

        try {
            m = (HashMap<Integer, Integer>) ois.readObject();
        }
        catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        ois.close();
        return m;
    }

    public static HashMap<Integer, Integer> readCurrent() {
        try {
            return read(PATH_CURRENT);
        }
        catch (FileNotFoundException e) {
            write(PATH_CURRENT, new HashMap<>());
            return readCurrent();
        }
        catch (IOException e) { throw new RuntimeException(e); }
    }

    public static KeyPair readKey(String path) throws IOException {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(path));
        KeyPair p;

        try {
            p = (KeyPair) ois.readObject();
        }
        catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }

        ois.close();
        return p;
    }

    public static void CORSHeaders(HttpExchange t) {
        t.getResponseHeaders().set("Access-Control-Allow-Origin", "*");
    }

    private class GetCurrent implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            CORSHeaders(exchange);

            JSONObject o = new JSONObject();

            for (Integer key : current.keySet()) {
                o.put(key, current.get(key));
            }

            exchange.sendResponseHeaders(200, o.toJSONString().getBytes().length);
            exchange.getResponseBody().write(o.toJSONString().getBytes());
        }
    }

    private class AddPoint implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            CORSHeaders(exchange);
            HashMap<String, String> query = (HashMap<String, String>) queryToMap(exchange.getRequestURI().getQuery());

            String out;
            if (!bypassKey) {
                ObjectInputStream ois = new ObjectInputStream(exchange.getRequestBody());
                EncryptedObject encryptedObject;

                try {
                    encryptedObject = (EncryptedObject) ois.readObject();
                } catch (ClassNotFoundException e) {
                    throw new RuntimeException(e);
                }

                ois.close();

                try {
                    out = (String) keyPair.decrypt(encryptedObject);
                } catch (PrivateKeyException e) {
                    throw new RuntimeException(e);
                }
            }
            else {
                out = CIPHER_STRING;
            }

            if (!out.equals(CIPHER_STRING)) {
                JSONObject fail = new JSONObject();
                fail.put("status", "fail");
                fail.put("message", "Invalid key");
                exchange.sendResponseHeaders(200, fail.toJSONString().getBytes().length);
                exchange.getResponseBody().write(fail.toJSONString().getBytes());
                return;
            }

            if (!query.containsKey("user")) {
                JSONObject fail = new JSONObject();
                fail.put("status", "fail");
                fail.put("message", "Missing user parameter");
                exchange.sendResponseHeaders(200, fail.toJSONString().getBytes().length);
                exchange.getResponseBody().write(fail.toJSONString().getBytes());
                return;
            }

            int user = Integer.parseInt(query.get("user"));
            if (current.containsKey(user)) {
                current.put(user, current.get(user) + 1);
            }
            else {
                current.put(user, 1);
            }

            write(PATH_CURRENT, current);


            JSONObject success = new JSONObject();
            success.put("status", "success");
            exchange.sendResponseHeaders(200, success.toJSONString().getBytes().length);
            exchange.getResponseBody().write(success.toJSONString().getBytes());
        }
    }
}