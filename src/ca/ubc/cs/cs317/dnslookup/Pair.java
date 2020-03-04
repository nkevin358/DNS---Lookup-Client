package ca.ubc.cs.cs317.dnslookup;

import java.util.Objects;

public class Pair {
    private String FQDN;
    private ResourceRecord record;
    private int currentIndex;

    public Pair() {}

    public Pair(String FQDN, int currentIndex) {
        this.FQDN = FQDN;
        this.currentIndex = currentIndex;
    }

    public Pair(ResourceRecord record, int currentIndex) {
        this.record = record;
        this.currentIndex = currentIndex;
    }

    public String getFQDN() {
        return FQDN;
    }

    public void setFQDN(String FQDN) {
        this.FQDN = FQDN;
    }

    public ResourceRecord getRecord() {
        return record;
    }

    public void setRecord(ResourceRecord record) {
        this.record = record;
    }

    public int getCurrentIndex() {
        return currentIndex;
    }

    public void setCurrentIndex(int currentIndex) {
        this.currentIndex = currentIndex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Pair pair = (Pair) o;
        return currentIndex == pair.currentIndex &&
                Objects.equals(FQDN, pair.FQDN);
    }

    @Override
    public int hashCode() {
        return Objects.hash(FQDN, currentIndex);
    }
}
