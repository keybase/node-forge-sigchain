default: build
all: build

ICED=node_modules/.bin/iced
JISON=node_modules/.bin/jison
BUILD_STAMP=build-stamp
TEST_STAMP=test-stamp
TEST_STAMP=test-stamp
UGLIFYJS=node_modules/.bin/uglifyjs
WD=`pwd`
BROWSERIFY=node_modules/.bin/browserify

BROWSER=browser/sigchain.js

lib/%.js: src/%.iced
	$(ICED) -I browserify -c -o `dirname $@` $<

$(BUILD_STAMP): \
	lib/main.js \
	lib/forge.js \
	lib/teamforge.js \
	lib/teamlib.js \
	lib/badprng.js \
	lib/util.js
	date > $@

clean:
	find lib -type f -name *.js -exec rm {} \;
	rm -rf $(BUILD_STAMP) $(TEST_STAMP) test/browser/test.js

setup:
	npm install -d

test: test-server

build: $(BUILD_STAMP)

test-server: $(BUILD_STAMP)
	$(ICED) test/run.iced

.PHONY: clean setup test  test-browser coverage
