NAME = ft_nmap
CC = gcc
CFLAGS = -Wall -Wextra -Werror -Iinc -MMD -MP

SRC_DIR = src
OBJ_DIR = obj

SRCS = $(shell find $(SRC_DIR) -name '*.c')
OBJS = $(SRCS:%.c=$(OBJ_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

# Default target
all: $(NAME)

# Create the binary
$(NAME): $(OBJS)
	@echo "🔗 Linking..."
	$(CC) $(CFLAGS) -o $@ $^

# Compile source files to object files with header tracking
$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	@echo "📦 Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Include dependency files
-include $(DEPS)

# Clean object files and dependency files
clean:
	@echo "🧹 Cleaning object files..."
	@rm -rf $(OBJ_DIR)

# Clean binary
fclean: clean
	@echo "🗑️ Removing binary..."
	@rm -f $(NAME)

# Rebuild everything
re: fclean all

.PHONY: all clean fclean re
