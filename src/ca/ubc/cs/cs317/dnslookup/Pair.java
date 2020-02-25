package ca.ubc.cs.cs317.dnslookup;

import java.util.Objects;

public class Pair {
    private String FQDN;
    private int endIndex;

    public Pair() {}

    public Pair(String FQDN, int endIndex) {
        this.FQDN = FQDN;
        this.endIndex = endIndex;
    }

    public String getFQDN() {
        return FQDN;
    }

    public void setFQDN(String FQDN) {
        this.FQDN = FQDN;
    }

    public int getEndIndex() {
        return endIndex;
    }

    public void setEndIndex(int endIndex) {
        this.endIndex = endIndex;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Pair pair = (Pair) o;
        return endIndex == pair.endIndex &&
                Objects.equals(FQDN, pair.FQDN);
    }

    @Override
    public int hashCode() {
        return Objects.hash(FQDN, endIndex);
    }
}
