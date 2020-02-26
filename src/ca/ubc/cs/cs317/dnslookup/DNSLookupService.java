package ca.ubc.cs.cs317.dnslookup;

import java.io.Console;
import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;

    private static DNSCache cache = DNSCache.getInstance();

    private static Random random = new Random();

    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2)
                    type = RecordType.A;
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }

        Set<ResourceRecord> results = cache.getCachedResults(node);

        // If Node is Cached return it
        if (!results.isEmpty()){
            return results;
        }

        // TODO need to do retrieveResultsFromServer for node and its type before changing it to CNAME type!!

        DNSNode nodeCNAME = new DNSNode(node.getHostName(), RecordType.CNAME );

        results = cache.getCachedResults(nodeCNAME);

        // Checks if CNAME is Cached
        if (results.isEmpty()){
            // Retrieve from Server
            retrieveResultsFromServer(node,rootServer);

            // Updates results with cache
            results = cache.getCachedResults(node);
            return results;
        }
        else {
            // CNAME is in Cache
            for (ResourceRecord cnameRecord : results) {
                DNSNode CNameRecord = new DNSNode(cnameRecord.getHostName(),cnameRecord.getType());
                // TODO Add a return somewhere
                getResults(CNameRecord, indirectionLevel + 1);
            }
        }

        // TODO To be completed by the student

        return cache.getCachedResults(node);
    }

    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) {
        // TODO
        try {
            byte[] requestQuery = new byte[512];

            requestQuery = encodeQuery(requestQuery, node);

            System.out.println(requestQuery[0]);
            System.out.println(requestQuery[1]);

            DatagramPacket request = new DatagramPacket(requestQuery, requestQuery.length, server, DEFAULT_DNS_PORT);

            socket.send(request);

            byte[] responseQuery = new byte[512];

            DatagramPacket response = new DatagramPacket(responseQuery,responseQuery.length);

            socket.receive(response);

            System.out.println(responseQuery[0]);
            System.out.println(responseQuery[1]);

            QueryTrace qt = decodeQuery(responseQuery, node);

            // TODO
            if (!qt.isAuthoritative()) {
                retrieveResultsFromServer(qt.getNode(), qt.getNameServers().get(0).getInetResult());
            }
        }
        catch (IOException e){
            System.out.println(e.getMessage());
        }
    }

    private static byte[] encodeQuery(byte[] query, DNSNode node){
        String[] QNAME = node.getHostName().split("\\.");
        Random rand = new Random();
        int queryID = rand.nextInt(65535);
        int ID1 =  (queryID >>> 8);
        int ID2 =  queryID & 0xff;

        query[0] = (byte) ID1;
        query[1] = (byte) ID2;

        // FLAGS
        query[2] = (byte) 0;
        query[3] = (byte) 0;

        // QueryTrace Count
        query[4] = (byte) 0;
        query[5] = (byte) 1;

        // Answer Count
        query[6] = (byte) 0;
        query[7] = (byte) 0;

        // Name Servers Records
        query[8] = (byte) 0;
        query[9] = (byte) 0;

        // Additional Record Count
        query[10] = (byte) 0;
        query[11] = (byte) 0;

        // QNAME
        int current = 12;
        for (int i=0 ; i < QNAME.length; i++){
            int length = QNAME[i].length();
            query[current] = (byte) length;
            current++;

            // byte[] array = QNAME[i].getBytes("UTF-8");

            for (int j =0; j < QNAME[i].length(); j++){
                char character = QNAME[i].charAt(j);
                int num = (int) character;

                query[current] = (byte) num;
                current++;
            }
        }

        // END of QNAME
        query[current] = (byte) 0;

        // QTYPE
        int QTYPE = node.getType().getCode();
        query[++current] = 0;
        query[++current] = (byte) QTYPE;

        // QCLASS
        query[++current] = (byte) 0;
        query[++current] = (byte) 1;

        return query;
    }

    private static QueryTrace decodeQuery(byte[] query, DNSNode node) {
        // use bytebuffer to know the length of the response
        // response is in big endian
        // bytebuffer, bytearrayinputstream, datainputstream

        // QueryID
        int queryID = twoBytesToInt(query[0], query[1]);

        // Check if AA is true or false
        int flagA = query[2];
        int QR = (flagA >> 7) & 1;
        int AA = (flagA >> 2) & 1;
        System.out.println("AA: " + AA);
        System.out.println("QR: " + QR);

        // Answer count
        int answerCount = twoBytesToInt(query[6], query[7]);
        System.out.println("AC: " + answerCount);

        // Name server count
        int nsCount = twoBytesToInt(query[8], query[9]);
        System.out.println("NS: " + nsCount);

        // Additional Record Count
        int arCount = twoBytesToInt(query[10], query[11]);
        System.out.println("AR: " + arCount);

        Pair pair = byteArrayToString(query, 12);
        String FQDN = pair.getFQDN();
        int endIndex = pair.getEndIndex();
        System.out.println(FQDN + " " + endIndex);

        // TODO
        // Decode answer
        if (AA == 1 && answerCount > 0) {
            decodeAnswer(query, endIndex);
        }

        // TODO
        // Decode authority
        decodeAuthority(query, endIndex);

        // TODO
        // Decode additional
        decodeAdditional(query, endIndex);

        // TODO
        return new QueryTrace();
    }

    private static int twoBytesToInt(byte a, byte b) {
        return (a << 8) | b & 0xFF;
    }

    // convert hex from byte[] to string to create FQDN
    private static Pair byteArrayToString(byte[] query, int current) {
        // TODO look into a better way to get current after this function runs
        int currentLen = query[current];
        System.out.println(currentLen);
        StringBuilder sb = new StringBuilder();

        while (currentLen != 0) {
            for (int i = 0; i < currentLen ; i++) {
                sb.append((char) query[++current]);
            }
            currentLen = query[++current];
            if (currentLen != 0) sb.append(".");
        }

        return new Pair(sb.toString(), ++current);
    }

    private static void decodeAnswer(byte[] query, int startIndex) {

    }

    private static void decodeAuthority(byte[] query, int startIndex) {

    }

    private static void decodeAdditional(byte[] query, int startIndex) {

    }

    // Decodes ResourceRecord
    private static ResourceRecord decodeResourceRecord(byte[] query, int startIndex){

        // Get first bit
        int pointer = getBit(query[startIndex], 7);
        Pair recordPair = new Pair();

        // Checks if there is a pointer
        if (pointer != 1) {
            recordPair = byteArrayToString(query, startIndex);
        }
        else {
            // TODO Handle Pointer domain name
        }

        int current = recordPair.getEndIndex();
        // Domain Name
        String hostName = recordPair.getFQDN();
        // Type
        int type = twoBytesToInt(query[current], query[++current]);
        RecordType recordType = RecordType.getByCode(type);
        // Class
        int recordClass = twoBytesToInt(query[++current], query[++current]);
        // TTL
        long TTL = getTTL(query, ++current);
        // Length
        current = current + 4;
        int len = twoBytesToInt(query[current], query[++current]);
        // Type is an Address 'A'
        InetAddress address = getAddress(query, ++current);
        // TODO check if address is not "A"

        ResourceRecord record =  new ResourceRecord(hostName, recordType , TTL, address);

        return record;
    }

    private static int getBit(byte x, int position){
        return (x >> position) & 1;
    }

    private static InetAddress getAddress(byte[] query, int startIndex){
        byte[] address = Arrays.copyOfRange(query, startIndex, (startIndex + 3));
        try {
            InetAddress IPv4add = InetAddress.getByAddress(address);
            return IPv4add;
        }
        catch (UnknownHostException e){
            System.out.println(e.getMessage());
            return null;
        }
    }

    private static int getTTL(byte[] query, int startIndex){
        byte[] TTL = Arrays.copyOfRange(query, startIndex, (startIndex + 3));

        ByteBuffer wrapped = ByteBuffer.wrap(TTL);

        return wrapped.getInt();
    }

    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
