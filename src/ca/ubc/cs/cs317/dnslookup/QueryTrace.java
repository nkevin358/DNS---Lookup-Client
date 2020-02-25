package ca.ubc.cs.cs317.dnslookup;

import java.net.InetAddress;
import java.util.List;
import java.util.Objects;

public class QueryTrace {
    private int queryId;
    private DNSNode node;
    private int responseId;
    private InetAddress server;
    private boolean isAuthoritative;
    private List<ResourceRecord> answers;
    private List<ResourceRecord> nameServers;
    private List<ResourceRecord> additional;

    // use verbosePrintResourceRecord() to print

    public QueryTrace() {}

    public QueryTrace(int queryId, DNSNode node, int responseId, InetAddress server, boolean isAuthoritative, List<ResourceRecord> answers, List<ResourceRecord> nameServers, List<ResourceRecord> additional) {
        this.queryId = queryId;
        this.node = node;
        this.responseId = responseId;
        this.server = server;
        this.isAuthoritative = isAuthoritative;
        this.answers = answers;
        this.nameServers = nameServers;
        this.additional = additional;
    }

    public int getQueryId() {
        return queryId;
    }

    public void setQueryId(int queryId) {
        this.queryId = queryId;
    }

    public DNSNode getNode() {
        return node;
    }

    public void setNode(DNSNode node) {
        this.node = node;
    }

    public int getResponseId() {
        return responseId;
    }

    public void setResponseId(int responseId) {
        this.responseId = responseId;
    }

    public InetAddress getServer() {
        return server;
    }

    public void setServer(InetAddress server) {
        this.server = server;
    }

    public boolean isAuthoritative() {
        return isAuthoritative;
    }

    public void setAuthoritative(boolean authoritative) {
        isAuthoritative = authoritative;
    }

    public List<ResourceRecord> getAnswers() {
        return answers;
    }

    public void setAnswers(List<ResourceRecord> answers) {
        this.answers = answers;
    }

    public List<ResourceRecord> getNameServers() {
        return nameServers;
    }

    public void setNameServers(List<ResourceRecord> nameServers) {
        this.nameServers = nameServers;
    }

    public List<ResourceRecord> getAdditional() {
        return additional;
    }

    public void setAdditional(List<ResourceRecord> additional) {
        this.additional = additional;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        QueryTrace that = (QueryTrace) o;
        return queryId == that.queryId &&
                responseId == that.responseId &&
                isAuthoritative == that.isAuthoritative &&
                Objects.equals(node, that.node) &&
                Objects.equals(server, that.server) &&
                Objects.equals(answers, that.answers) &&
                Objects.equals(nameServers, that.nameServers) &&
                Objects.equals(additional, that.additional);
    }

    @Override
    public int hashCode() {
        return Objects.hash(queryId, node, responseId, server, isAuthoritative, answers, nameServers, additional);
    }
}
