.PHONY: performance comparison crossversion

performance:
	$(MAKE) -C performance bench

comparison:
	cd comparison && go test -bench . -benchmem -count 5 -timeout 60m

crossversion:
	$(MAKE) -C crossversion compare
