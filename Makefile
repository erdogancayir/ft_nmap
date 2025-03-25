NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -Iinc -MMD -MP

SRC_DIR = src
OBJ_DIR = obj
TEST_DIR = tests

SRCS = $(shell find $(SRC_DIR) -name '*.c')
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

TEST_NAME = test
TEST_SRC = $(TEST_DIR)/test_parse_args.c
TEST_OBJ = $(TEST_SRC:%.c=$(OBJ_DIR)/%.o)

MAIN_OBJ := $(OBJ_DIR)/src/main.o
OBJS_NO_MAIN := $(filter-out $(MAIN_OBJ), $(OBJS))

# Default target
all: $(NAME)

# Create the binary
$(NAME): $(OBJS)
	@echo "🔗 Linking $(NAME)..."
	@$(CC) $(CFLAGS) -o $@ $^

# Compile source files to object files
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "📦 Compiling $<..."
	@$(CC) $(CFLAGS) -c $< -o $@ || (echo "❌ Compile error in $<"; exit 1)

# Build and run the test binary
test: $(TEST_NAME)
	@echo "🚀 Running tests..."
	./$(TEST_NAME)

$(TEST_NAME): $(TEST_OBJ) $(OBJS_NO_MAIN)
	@echo "🧪 Linking test binary..."
	@$(CC) $(CFLAGS) -o $@ $^

# Include dependency files
-include $(DEPS)

# Clean object files and dependency files
clean:
	@echo "🧹 Cleaning object files..."
	@rm -rf $(OBJ_DIR)

# Clean binaries
fclean: clean
	@echo "🗑️ Removing binaries..."
	@rm -f $(NAME) $(TEST_NAME)

# Rebuild everything
re: fclean all