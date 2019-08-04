gen := test-gen/gen.py

src/pyca-test-vectors.in: test-gen/pyca-test-vectors.py $(gen)
	$(gen) $< > $@
