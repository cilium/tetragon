TESTDATA_URL = https://github.com/cilium/tetragon-testdata/raw/main/pclntab

all: node_exporter-stripped node_exporter-unstripped node_exporter-go122-stripped

%.gz:
	wget -nv -O $@ '$(TESTDATA_URL)/$@'

%: %.gz
	gunzip -k $<

clean:
	rm -f node_exporter-stripped node_exporter-unstripped node_exporter-go122-stripped
	rm -f node_exporter-stripped.gz node_exporter-unstripped.gz node_exporter-go122-stripped.gz

.PHONY: all clean
