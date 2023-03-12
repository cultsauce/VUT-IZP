/*>>>>>>>  PASSWORD STRENGTH CHECKER  <<<<<<*
 *>>>>>>>>>>>>> TEREZA KUBINCOVA <<<<<<<<<<<*
 *>>>>>>>>>>>>>>>>> xkubin27 <<<<<<<<<<<<<<<*/

#include <stdio.h>

#define MAX_PSWD_LEN     100 
#define MAX_DIFF_CHARS   256

#define MAX_LEVEL        4
#define MIN_LEVEL        1

#define RETURN_SUCESS    0
#define RETURN_FAILURE  -1

//returns 1 if  a character is uppercase, returns 0 otherwise
int isUpper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

//returns 1 if  a character is lowercase, returns 0 otherwise
int isLower(char c)
{
    return (c >= 'a' && c <= 'z');
}

//returns 1 if  a character is a special character in the range 32 - 126, returns 0 otherwise
int isSpecial(char c)
{
    return ((c >= 32 && c <= 47) || (c >= 58 && c <= 64) || (c >= 91 && c <= 96) || (c >= 123 && c <= 126));
}

//returns 1 if a character is numeric, returns 0 otherwise
int isNum(char c)
{
    return (c >= '0' && c <= '9');
}

//compare two parts of the same string specified by start indices, returns 0 otherwise
int compareSubstrings(char str[], int strLen, int start1, int start2, int len)
{
    // check if a out-of-bounds interval wasn't specified
    if (start1 + len > strLen || start2 + len > strLen) return 0;

    for (int i = start1, j = start2; i - start1 < len  && j - start2 < len; i++, j++)
    {
        if (str[i] != str[j]) return 0;
    }
    return 1;
}

//calculate the length of a string
int getStrLen(char str[])
{
    int i = 0;
    while (str[i] != '\0' && str[i] != '\n')
    {
        i++;
    }

    return i;
}

//convert a string to its integer value, returns 0 if a problem happens during conversion, otherwise returns 1
int stringToInt(char str[], int *ptr)
{
    // if a number looks like an octal literal it is not accepted as a valid integer (ex. 08)
    if (getStrLen(str) > 1 && str[0] == '0') return 0;

    // do the conversion
    int num = 0;
    for (int i = getStrLen(str) - 1, j = 1; i >= 0; i--, j *= 10)
    {
        if (!isNum(str[i])) return 0;

        num += (str[i] - '0') * j;

        // check if the operation did not result in overflow, if yes set the value of param to 101 (never reachable with a max length of 100)
        if (num/j != str[i] - '0') num = MAX_PSWD_LEN + 1; 
    }

     // if the whole conversion goes ok, modify the int pointed to by *ptr
    *ptr = num;
    return 1;
}

//returns 1 if the two strings are equal, returns 0 otherwise
int strCompare(char str1[], char str2[])
{
    int i = 0;
    while (str1[i] != '\0' && str2[i] != '\0') 
    {
        if (str1[i] != str2[i])
        {
            return 0;
        }
        i++;
    }
    if (str1[i] == '\0' && str2[i] == '\0')
    {
        return 1;
    }
    else return 0;
}

// return 1 if a password passed level 1 (contains both a lowercase and uppercase letter), otherwise returns 0
int levelOne(char psswd[], int psswdLen)
{
    int hasUpper = 0, hasLower = 0;
    for (int i = 0; i < psswdLen; i++)
    {
        if (isLower(psswd[i]))
        {
            hasLower = 1;
        }
        else if (isUpper(psswd[i]))
        {
            hasUpper = 1;
        }
        if (hasLower == 1 && hasUpper == 1)
        {
            return 1;
        }
    }
    return 0;  
}

//returns 1 if the password passes level 2 -- password contains characters from X (param) categories (or if if param is greater than 4 = from all categories considered), returns 0 otherwise
int levelTwo(char psswd[], int psswdLen, int param)
{
    if (!levelOne(psswd, psswdLen)) return 0; // the password did not pass level 1, so it cannot be level 2

    //since the password already passed level one, we know it has both a capital and lowercase letter, we only need to check for special and numeric
    int conditionsMet = 2;
    int hasNum = 0, hasSpecial = 0;

    for (int i = 0; i < psswdLen; i++)
    {
        if (hasNum == 0 && isNum(psswd[i]))
        {
            hasNum = 1;
            conditionsMet++;
        }
        else if (hasSpecial == 0 && isSpecial(psswd[i]))
        {
            hasSpecial = 1;
            conditionsMet++;
        }
        if (conditionsMet >= param || conditionsMet == 4)
            return 1;
    }
    return 0;
}

//returns 1 if the password passes level 3 - password doesn't contain a sequence of the same characters of length X (param), returns 0 otherwise
int levelThree(char psswd[], int psswdLen, int param)
{
    if (!levelTwo(psswd, psswdLen, param)) return 0;  // the password did not pass level 2 or 1, meaning it cannot be level 3

    int count = 1;  // counter for occurences of the same character
    char currentChar = psswd[0];
    for (int i = 1; i < psswdLen && count < param; i++)
    {
        if (currentChar == psswd[i])
            count++;
        else
        {
            currentChar = psswd[i];
            count = 1;
        }
    }
    if (count >= param)  // a sequence of length X was found, the password is not valid
        return 0;
    else 
        return 1; // no sequence found, the password is valid
}

//returns 1 if the password passes level 4 - the password does not contain two equal substrings of length X (param), returns 0 otherwise
int levelFour(char psswd[], int psswdLen, int param)
{
    if (!levelThree(psswd, psswdLen, param)) return 0; // the password did not pass level 1, 2 or 3, meaning it cannot be level 4

    for (int i = 0; i < psswdLen - param; i++)
    {
        for (int j = i + 1; j < psswdLen - param + 1; j++)
        {
            if (compareSubstrings(psswd, psswdLen, i, j, param))
                return 0;
        }
    }
    return 1; // no two equal substrings found, the password is valid
}

// pass the password to the corresponding function for the level specified
int levelHandler(char psswd[], int psswdLen, int level, int param)
{
    switch (level)
    {
        case 1: return levelOne(psswd, psswdLen);
        case 2: return levelTwo(psswd, psswdLen, param);
        case 3: return levelThree(psswd, psswdLen, param);
        case 4: return levelFour(psswd, psswdLen, param);
        default: return RETURN_FAILURE; // in case a wrong level value is passed
    }
}

int checkPasswordList(int level, int param, int stats)
{
    int nChars = 0, nDiffChars = 0, minLen = 0, nPsswd = 0;
    char charactersUsed[MAX_DIFF_CHARS + 1] = {0};

    // size constists of max length of 100 character, newline (fgets saves it) and the null character
    char psswd[MAX_PSWD_LEN + 2];

    //read passwords from stdin until EOF or the maximum length (n - 1) is reached
    for (nPsswd = 0; fgets(psswd, MAX_PSWD_LEN + 2, stdin) != NULL; nPsswd++)
    {
        // if the next character isn't newline then we know the password is over 100 chars long
        int psswdLen = getStrLen(psswd);
        if (psswd[psswdLen] != '\n')
        {
            fprintf(stderr, "Password exceeds maximum length of 100 characters.\n");
            return RETURN_FAILURE;
        }
        
        // update the number of different characters statistic
        for (int i = 0; i < psswdLen; i++)
        {
            if ((unsigned int) psswd[i] > 255) 
            {
                fprintf(stderr, "The password contains characters that are not part of the standard ASCII table.\n");
                return RETURN_FAILURE;
            }

            else if (charactersUsed[(unsigned int)psswd[i]] != 1)
            {
                charactersUsed[(unsigned int)psswd[i]] = 1;
                nDiffChars++;
            }
        }
        nChars += psswdLen;

        //update shortest password statistic
        if (nPsswd == 0 || minLen > psswdLen) minLen = psswdLen;

        // if the password passes the level specified, print it
        if (levelHandler(psswd, psswdLen, level, param)) printf("%s", psswd);
    }

    // display password statistics if it is required
    if (stats)
        printf("Statistika:\nRuznych znaku: %d\n"
                "Minimalni delka: %d\n"
                "Prumerna delka: %.1f\n", nDiffChars, minLen, 
                (nPsswd == 0) ? (0.0f) : (nChars/ (float)nPsswd)); // if the number of passwords is zero, avoid zero division by just printing 0.0

    return RETURN_SUCESS;
}

int main(int argc, char *argv[])
{
    // default values if no arguments are specified
    int level = 1, param = 1, stats = 0;

    // first check for normal arguments (without flags)
    if (argc == 3 && stringToInt(argv[1], &level) && stringToInt(argv[2], &param))
    {
        stats = 0;
    }
    else if (argc == 4 && stringToInt(argv[1], &level) && stringToInt(argv[2], &param) && strCompare(argv[3], "--stats"))
    {
        stats = 1;
    }

    // arguments with flags
    else if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            if (strCompare(argv[i], "-l") && i + 1 < argc && stringToInt(argv[i + 1], &level))
            {
                i++;
            }
            else if (strCompare(argv[i], "-p") && i + 1 < argc && stringToInt(argv[i + 1], &param))
            {
                i++;
            }
            else if (strCompare(argv[i], "--stats"))
            {
                stats = 1;
            }
            else
            {
                fprintf(stderr, "Invalid arguments supplied.\n");
                return RETURN_FAILURE;
            }
        }
    }

    // check if LEVEL and PARAM are within allowed range
    if (!(level >= MIN_LEVEL) || !(level <= MAX_LEVEL) || param < 1)
    {
        fprintf(stderr, "LEVEL has to be in the range <1, 4> and PARAM has to be a positive integer\n");
        return RETURN_FAILURE;
    }

    // argument validation went ok, proceed to check the passwords
    return checkPasswordList(level, param, stats);
}