NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -Iinc -MMD -MP
LDLIBS = -lpcap

SRC_DIR = src
OBJ_DIR = obj
TEST_DIR = tests

SRCS = $(shell find $(SRC_DIR) -name '*.c')
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

MAIN_OBJ = $(OBJ_DIR)/src/main.o
OBJS_NO_MAIN = $(filter-out $(MAIN_OBJ), $(OBJS))

# Test dosyalarını otomatik seç
TEST_SRCS = $(shell find $(TEST_DIR) -name '*.c')
TEST_OBJS = $(TEST_SRCS:%.c=$(OBJ_DIR)/%.o)

TEST_NAME = ft_nmap_tests

# Default target
all: $(NAME)

# Debug build
debug: export CFLAGS += -DDEBUG -g
debug: re

# Uygulama binary'si
$(NAME): $(OBJS)
	@echo "🔗 Linking $(NAME)..."
	@$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

# Nesne dosyaları oluştur
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "📦 Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@ || (echo "❌ Compile error in $<"; exit 1)

# Testleri derle ve çalıştır
test: $(TEST_NAME)
	@echo "🚀 Running tests..."
	@./$(TEST_NAME)

$(TEST_NAME): $(TEST_OBJS) $(OBJS_NO_MAIN)
	@echo "🧪 Linking test binary..."
	@$(CC) $(CFLAGS) -o $@ $^ $(LDLIBS)

-include $(DEPS)

clean:
	@echo "🧹 Cleaning object files..."
	@rm -rf $(OBJ_DIR)

fclean: clean
	@echo "🗑️ Removing binaries..."
	@rm -f $(NAME) $(TEST_NAME)

re: fclean all

.PHONY: all clean fclean re test
