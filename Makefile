ARCH         ?= arm64
SDK          ?= iphoneos
CORE_DIR     ?= core
ENTITLEMENTS ?= entitlements.plist
SIGNING_ID   ?= "XXX"
DIAGNOSTIC   ?= 0

NAME    := chain3
IPA     := $(NAME).ipa
PACKAGE := foxhound.chain3

ifneq ($(ARCH),x86_64)
CLANG    := $(shell xcrun --sdk $(SDK) --find clang)
AR       := $(shell xcrun --sdk $(SDK) --find ar)
ifeq ($(CLANG),)
$(error Could not find clang for SDK $(SDK))
endif
SYSROOT  := $(shell xcrun --sdk $(SDK) --show-sdk-path)
CC       := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)
endif
CODESIGN := codesign

SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
BIN_DIR = bin
RES_DIR = res

#ERRFLAGS   = -Wall -Wpedantic -Wno-gnu -Werror -Wunused-variable
#CFLAGS     = 
LDFLAGS    = -g -lcompression
FRAMEWORKS = -framework Foundation -framework IOKit -framework UIKit
ARFLAGS    = r

CFLAGS    = -g -O2 $(ERRFLAGS) -I$(INC_DIR) -mios-version-min=11.2 -DDEBUG=1

SRC_FILES = main.m iosurface.m helper.m applevxd393.m spray.m exploit.m ViewController.m AppDelegate.m

SRC = $(SRC_FILES:%=$(SRC_DIR)/%)
OBJ = $(SRC:$(SRC_DIR)/%.m=$(OBJ_DIR)/%.o)

ifneq ($(ENTITLEMENTS),)
ifneq ($(wildcard $(ENTITLEMENTS)),)
CODESIGN_FLAGS = --entitlements "$(ENTITLEMENTS)"
endif
endif

ifeq ($(SIGNING_ID),)
CODESIGN_COMMAND = @true
else
CODESIGN_COMMAND = $(CODESIGN) $(CODESIGN_FLAGS) -s $(SIGNING_ID)
endif

BIN := $(BIN_DIR)/$(NAME)
APP_DIR := $(BIN_DIR)/Payload/$(NAME).app/

.PHONY: all clean install

all: $(BIN)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.m
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJ)
	@mkdir -p $(@D)
	@mkdir -p $(APP_DIR)
	echo $(OBJ)
	$(CC) $(LDFLAGS) $(FRAMEWORKS) $(OBJ) -o $@
	sed 's/$$(NAME)/$(NAME)/g;s/$$(PACKAGE)/$(PACKAGE)/g' $(RES_DIR)/Info.plist > $(APP_DIR)/Info.plist
	cp $@ $(APP_DIR)
	$(CODESIGN_COMMAND) $(APP_DIR)$(NAME)
	cd $(@D) && zip -x .DS_Store -r ../$(IPA) Payload

install:
	ideviceinstaller -i $(IPA)

clean:
	rm -rf -- $(OBJ_DIR) $(BIN_DIR) $(LIB_DIR)
