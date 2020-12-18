#ifndef COLOR_H
#define COLOR_H

// Reset
#define COLOR_OFF "\033[0m"
#define COLOR_BG_OFF "\033[49m"

// Regular Colors
#define BLACK "\033[0;30m"
#define RED "\033[0;31m"
#define GREEN "\033[0;32m"
#define YELLOW "\033[0;33m"
#define BLUE "\033[0;34m"
#define PURPLE "\033[0;35m"
#define CYAN "\033[0;36m"
#define WHITE "\033[0;37m"

// Bold
#define B_BLACK "\033[1;30m"
#define B_RED "\033[1;31m"
#define B_GREEN "\033[1;32m"
#define B_YELLOW "\033[1;33m"
#define B_BLUE "\033[1;34m"
#define B_PURPLE "\033[1;35m"
#define B_CYAN "\033[1;36m"
#define B_WHITE "\033[1;37m"

// Underline
#define U_BLACK "\033[4;30m"
#define U_RED "\033[4;31m"
#define U_GREEN "\033[4;32m"
#define U_YELLOW "\033[4;33m"
#define U_BLUE "\033[4;34m"
#define U_PURPLE "\033[4;35m"
#define U_CYAN "\033[4;36m"
#define U_WHITE "\033[4;37m"

// Background
#define BG_BLACK "\033[40m"
#define BG_RED "\033[41m"
#define BG_GREEN "\033[42m"
#define BG_YELLOW "\033[43m"
#define BG_BLUE "\033[44m"
#define BG_PURPLE "\033[45m"
#define BG_CYAN "\033[46m"
#define BG_WHITE "\033[47m"

// High Intensity
#define I_BLACK "\033[0;90m"
#define I_RED "\033[0;91m"
#define I_GREEN "\033[0;92m"
#define I_YELLOW "\033[0;93m"
#define I_BLUE "\033[0;94m"
#define I_PURPLE "\033[0;95m"
#define I_CYAN "\033[0;96m"
#define I_WHITE "\033[0;97m"

// Bold High Intensity
#define BI_BLACK "\033[1;90m"
#define BI_RED "\033[1;91m"
#define BI_GREEN "\033[1;92m"
#define BI_YELLOW "\033[1;93m"
#define BI_BLUE "\033[1;94m"
#define BI_PURPLE "\033[1;95m"
#define BI_CYAN "\033[1;96m"
#define BI_WHITE "\033[1;97m"

// High Intensity backgrounds
#define BG_I_BLACK "\033[0;100m"
#define BG_I_RED "\033[0;101m"
#define BG_I_GREEN "\033[0;102m"
#define BG_I_YELLOW "\033[0;103m"
#define BG_I_BLUE "\033[0;104m"
#define BG_I_PURPLE "\033[0;105m"
#define BG_I_CYAN "\033[0;106m"
#define BG_I_WHITE "\033[0;107m"

/**
 * @brief Print the text with a black background.
 * 
 * @param txt: the text.
 */
void print_b_blue(char *txt, int new_line);

/**
 * @brief Print the text with a red background.
 * 
 * @param txt: the text.
 */
void print_bg_red(char *txt, int new_line);

/**
 * @brief Print the text with a green background.
 * 
 * @param txt: the text.
 */
void print_bg_green(char *txt, int new_line);

/**
 * @brief Print the text with a yellow background.
 * 
 * @param txt: the text.
 */
void print_bg_yellow(char *txt, int new_line);

/**
 * @brief Print the text with a blue background.
 * 
 * @param txt: the text.
 */
void print_bg_blue(char *txt, int new_line);

/**
 * @brief Print the text with a purple background.
 * 
 * @param txt: the text.
 */
void print_bg_purple(char *txt, int new_line);

/**
 * @brief Print the text with a cyan background.
 * 
 * @param txt: the text.
 */
void print_bg_cyan(char *txt, int new_line);

/**
 * @brief Print the text with a white background.
 * 
 * @param txt: the text.
 */
void print_bg_white(char *txt, int new_line);

/**
 * @brief Print the text with a black background.
 * 
 * @param txt: the text.
 */
void print_i_bg_black(char *txt, int new_line);

/**
 * @brief Print the text with a red background.
 * 
 * @param txt: the text.
 */
void print_i_bg_red(char *txt, int new_line);

/**
 * @brief Print the text with a green background.
 * 
 * @param txt: the text.
 */
void print_i_bg_green(char *txt, int new_line);

/**
 * @brief Print the text with a yellow background.
 * 
 * @param txt: the text.
 */
void print_i_bg_yellow(char *txt, int new_line);

/**
 * @brief Print the text with a blue background.
 * 
 * @param txt: the text.
 */
void print_i_bg_blue(char *txt, int new_line);

/**
 * @brief Print the text with a purple background.
 * 
 * @param txt: the text.
 */
void print_i_bg_purple(char *txt, int new_line);

/**
 * @brief Print the text with a cyan background.
 * 
 * @param txt: the text.
 */
void print_i_bg_cyan(char *txt, int new_line);

/**
 * @brief Print the text with a white background.
 * 
 * @param txt: the text.
 */
void print_b_green(char *txt, int new_line);

#endif //COLOR_H