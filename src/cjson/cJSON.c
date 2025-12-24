/*
  Copyright (c) 2009-2017 Dave Gamble and cJSON contributors
  
  Minimal cJSON implementation for Nginx module.
  Full source available at: https://github.com/DaveGamble/cJSON
  
  This is a simplified version - for production use, include the full cJSON library.
*/

#include <string.h>
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include "cJSON.h"

static void *(*cJSON_malloc)(size_t sz) = malloc;
static void (*cJSON_free)(void *ptr) = free;

void cJSON_InitHooks(cJSON_Hooks* hooks)
{
    if (hooks == NULL) {
        cJSON_malloc = malloc;
        cJSON_free = free;
        return;
    }

    cJSON_malloc = (hooks->malloc_fn) ? hooks->malloc_fn : malloc;
    cJSON_free = (hooks->free_fn) ? hooks->free_fn : free;
}

static cJSON *cJSON_New_Item(void)
{
    cJSON* node = (cJSON*)cJSON_malloc(sizeof(cJSON));
    if (node) {
        memset(node, 0, sizeof(cJSON));
    }
    return node;
}

void cJSON_Delete(cJSON *item)
{
    cJSON *next = NULL;
    while (item != NULL) {
        next = item->next;
        if (!(item->type & cJSON_IsReference) && (item->child != NULL)) {
            cJSON_Delete(item->child);
        }
        if (!(item->type & cJSON_IsReference) && (item->valuestring != NULL)) {
            cJSON_free(item->valuestring);
        }
        if (!(item->type & cJSON_StringIsConst) && (item->string != NULL)) {
            cJSON_free(item->string);
        }
        cJSON_free(item);
        item = next;
    }
}

/* Type checking functions */
int cJSON_IsInvalid(const cJSON * const item) { return (item == NULL) || ((item->type & 0xFF) == cJSON_Invalid); }
int cJSON_IsFalse(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_False); }
int cJSON_IsTrue(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_True); }
int cJSON_IsBool(const cJSON * const item) { return (item != NULL) && (((item->type & 0xFF) == cJSON_True) || ((item->type & 0xFF) == cJSON_False)); }
int cJSON_IsNull(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_NULL); }
int cJSON_IsNumber(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_Number); }
int cJSON_IsString(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_String); }
int cJSON_IsArray(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_Array); }
int cJSON_IsObject(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_Object); }
int cJSON_IsRaw(const cJSON * const item) { return (item != NULL) && ((item->type & 0xFF) == cJSON_Raw); }

/* Create functions */
cJSON *cJSON_CreateNull(void) { cJSON *item = cJSON_New_Item(); if(item) item->type = cJSON_NULL; return item; }
cJSON *cJSON_CreateTrue(void) { cJSON *item = cJSON_New_Item(); if(item) item->type = cJSON_True; return item; }
cJSON *cJSON_CreateFalse(void) { cJSON *item = cJSON_New_Item(); if(item) item->type = cJSON_False; return item; }
cJSON *cJSON_CreateBool(int b) { cJSON *item = cJSON_New_Item(); if(item) item->type = b ? cJSON_True : cJSON_False; return item; }

cJSON *cJSON_CreateNumber(double num)
{
    cJSON *item = cJSON_New_Item();
    if (item) {
        item->type = cJSON_Number;
        item->valuedouble = num;
        item->valueint = (int)num;
    }
    return item;
}

cJSON *cJSON_CreateString(const char *string)
{
    cJSON *item = cJSON_New_Item();
    if (item) {
        item->type = cJSON_String;
        item->valuestring = (string != NULL) ? strdup(string) : NULL;
    }
    return item;
}

cJSON *cJSON_CreateRaw(const char *raw)
{
    cJSON *item = cJSON_New_Item();
    if (item) {
        item->type = cJSON_Raw;
        item->valuestring = (raw != NULL) ? strdup(raw) : NULL;
    }
    return item;
}

cJSON *cJSON_CreateArray(void) { cJSON *item = cJSON_New_Item(); if(item) item->type = cJSON_Array; return item; }
cJSON *cJSON_CreateObject(void) { cJSON *item = cJSON_New_Item(); if(item) item->type = cJSON_Object; return item; }

/* Array/Object functions */
int cJSON_GetArraySize(const cJSON *array)
{
    cJSON *child = NULL;
    size_t size = 0;

    if (array == NULL) return 0;

    child = array->child;
    while (child != NULL) {
        size++;
        child = child->next;
    }
    return (int)size;
}

cJSON *cJSON_GetArrayItem(const cJSON *array, int index)
{
    cJSON *current_child = NULL;

    if (array == NULL || index < 0) return NULL;

    current_child = array->child;
    while ((current_child != NULL) && (index > 0)) {
        index--;
        current_child = current_child->next;
    }
    return current_child;
}

cJSON *cJSON_GetObjectItem(const cJSON *object, const char *string)
{
    cJSON *current_element = NULL;

    if ((object == NULL) || (string == NULL)) return NULL;

    current_element = object->child;
    while ((current_element != NULL) && (current_element->string != NULL) && 
           (strcasecmp(current_element->string, string) != 0)) {
        current_element = current_element->next;
    }
    return current_element;
}

cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *object, const char *string)
{
    cJSON *current_element = NULL;

    if ((object == NULL) || (string == NULL)) return NULL;

    current_element = object->child;
    while ((current_element != NULL) && (current_element->string != NULL) && 
           (strcmp(current_element->string, string) != 0)) {
        current_element = current_element->next;
    }
    return current_element;
}

int cJSON_HasObjectItem(const cJSON *object, const char *string)
{
    return cJSON_GetObjectItem(object, string) != NULL;
}

static void suffix_object(cJSON *prev, cJSON *item)
{
    prev->next = item;
    item->prev = prev;
}

void cJSON_AddItemToArray(cJSON *array, cJSON *item)
{
    cJSON *child = NULL;

    if ((item == NULL) || (array == NULL)) return;

    child = array->child;
    if (child == NULL) {
        array->child = item;
    } else {
        while (child->next) {
            child = child->next;
        }
        suffix_object(child, item);
    }
}

void cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item)
{
    if ((item == NULL) || (string == NULL)) return;

    if (item->string) {
        cJSON_free(item->string);
    }
    item->string = strdup(string);
    cJSON_AddItemToArray(object, item);
}

/* Simplified print function */
static char *print_number(const cJSON *item)
{
    char *output = NULL;
    double d = item->valuedouble;

    output = (char*)cJSON_malloc(64);
    if (output == NULL) return NULL;

    if (floor(d) == d && fabs(d) < 1.0e15) {
        sprintf(output, "%.0f", d);
    } else {
        sprintf(output, "%g", d);
    }
    return output;
}

static char *print_string(const char *str)
{
    char *output = NULL;
    size_t len;

    if (str == NULL) {
        output = (char*)cJSON_malloc(3);
        if (output) strcpy(output, "\"\"");
        return output;
    }

    len = strlen(str) + 3;
    output = (char*)cJSON_malloc(len);
    if (output) {
        sprintf(output, "\"%s\"", str);
    }
    return output;
}

static char *print_value(const cJSON *item, int depth, int fmt);

static char *print_array(const cJSON *item, int depth, int fmt)
{
    char **entries;
    char *out = NULL, *ptr, *ret;
    size_t len = 5;
    cJSON *child = item->child;
    int numentries = 0, i = 0;

    while (child) { numentries++; child = child->next; }
    if (!numentries) {
        out = (char*)cJSON_malloc(3);
        if (out) strcpy(out, "[]");
        return out;
    }

    entries = (char**)cJSON_malloc(numentries * sizeof(char*));
    if (!entries) return NULL;
    memset(entries, 0, numentries * sizeof(char*));

    child = item->child;
    while (child && i < numentries) {
        ret = print_value(child, depth + 1, fmt);
        entries[i++] = ret;
        if (ret) len += strlen(ret) + 2 + (fmt ? 1 : 0);
        child = child->next;
    }

    out = (char*)cJSON_malloc(len);
    if (!out) {
        for (i = 0; i < numentries; i++) if (entries[i]) cJSON_free(entries[i]);
        cJSON_free(entries);
        return NULL;
    }

    *out = '[';
    ptr = out + 1;
    for (i = 0; i < numentries; i++) {
        if (entries[i]) {
            strcpy(ptr, entries[i]);
            ptr += strlen(entries[i]);
            if (i != numentries - 1) { *ptr++ = ','; if (fmt) *ptr++ = ' '; }
            cJSON_free(entries[i]);
        }
    }
    *ptr++ = ']';
    *ptr = '\0';
    cJSON_free(entries);
    return out;
}

static char *print_object(const cJSON *item, int depth, int fmt)
{
    char **entries = NULL, **names = NULL;
    char *out = NULL, *ptr, *ret, *str;
    size_t len = 7;
    cJSON *child = item->child;
    int numentries = 0, i = 0;

    while (child) { numentries++; child = child->next; }
    if (!numentries) {
        out = (char*)cJSON_malloc(3);
        if (out) strcpy(out, "{}");
        return out;
    }

    entries = (char**)cJSON_malloc(numentries * sizeof(char*));
    names = (char**)cJSON_malloc(numentries * sizeof(char*));
    if (!entries || !names) {
        if (entries) cJSON_free(entries);
        if (names) cJSON_free(names);
        return NULL;
    }
    memset(entries, 0, numentries * sizeof(char*));
    memset(names, 0, numentries * sizeof(char*));

    child = item->child;
    while (child && i < numentries) {
        names[i] = str = print_string(child->string);
        entries[i++] = ret = print_value(child, depth + 1, fmt);
        if (str && ret) len += strlen(ret) + strlen(str) + 2 + (fmt ? 3 : 0);
        child = child->next;
    }

    out = (char*)cJSON_malloc(len);
    if (!out) {
        for (i = 0; i < numentries; i++) {
            if (names[i]) cJSON_free(names[i]);
            if (entries[i]) cJSON_free(entries[i]);
        }
        cJSON_free(names);
        cJSON_free(entries);
        return NULL;
    }

    *out = '{';
    ptr = out + 1;
    for (i = 0; i < numentries; i++) {
        if (names[i] && entries[i]) {
            strcpy(ptr, names[i]); ptr += strlen(names[i]);
            *ptr++ = ':';
            if (fmt) *ptr++ = ' ';
            strcpy(ptr, entries[i]); ptr += strlen(entries[i]);
            if (i != numentries - 1) *ptr++ = ',';
            if (fmt) *ptr++ = ' ';
            cJSON_free(names[i]);
            cJSON_free(entries[i]);
        }
    }
    *ptr++ = '}';
    *ptr = '\0';
    cJSON_free(names);
    cJSON_free(entries);
    return out;
}

static char *print_value(const cJSON *item, int depth, int fmt)
{
    char *out = NULL;

    if (!item) return NULL;

    switch ((item->type) & 0xFF) {
        case cJSON_NULL:   out = strdup("null"); break;
        case cJSON_False:  out = strdup("false"); break;
        case cJSON_True:   out = strdup("true"); break;
        case cJSON_Number: out = print_number(item); break;
        case cJSON_String: out = print_string(item->valuestring); break;
        case cJSON_Raw:    out = strdup(item->valuestring ? item->valuestring : ""); break;
        case cJSON_Array:  out = print_array(item, depth, fmt); break;
        case cJSON_Object: out = print_object(item, depth, fmt); break;
    }
    return out;
}

char *cJSON_Print(const cJSON *item) { return print_value(item, 0, 1); }
char *cJSON_PrintUnformatted(const cJSON *item) { return print_value(item, 0, 0); }

/* Simplified parse function - basic implementation */
static const char *skip_whitespace(const char *in)
{
    while (in && *in && ((unsigned char)*in <= 32)) in++;
    return in;
}

static cJSON *parse_value(const char **value);

static const char *parse_number(cJSON *item, const char *num)
{
    double n = 0, sign = 1, scale = 0;
    int subscale = 0, signsubscale = 1;

    if (*num == '-') { sign = -1; num++; }
    if (*num == '0') num++;
    if (*num >= '1' && *num <= '9') {
        do { n = (n * 10.0) + (*num++ - '0'); } while (*num >= '0' && *num <= '9');
    }
    if (*num == '.' && num[1] >= '0' && num[1] <= '9') {
        num++;
        do { n = (n * 10.0) + (*num++ - '0'); scale--; } while (*num >= '0' && *num <= '9');
    }
    if (*num == 'e' || *num == 'E') {
        num++;
        if (*num == '+') num++;
        else if (*num == '-') { signsubscale = -1; num++; }
        while (*num >= '0' && *num <= '9') subscale = (subscale * 10) + (*num++ - '0');
    }

    n = sign * n * pow(10.0, (scale + subscale * signsubscale));
    item->valuedouble = n;
    item->valueint = (int)n;
    item->type = cJSON_Number;
    return num;
}

static const char *parse_string(cJSON *item, const char *str)
{
    const char *ptr = str + 1;
    char *out;
    int len = 0;
    const char *ptr2;

    if (*str != '\"') return NULL;

    while (*ptr != '\"' && *ptr) { if (*ptr++ == '\\') ptr++; len++; }

    out = (char*)cJSON_malloc(len + 1);
    if (!out) return NULL;

    ptr = str + 1;
    ptr2 = out;
    while (*ptr != '\"' && *ptr) {
        if (*ptr != '\\') *((char*)ptr2++) = *ptr++;
        else {
            ptr++;
            switch (*ptr) {
                case 'b': *((char*)ptr2++) = '\b'; break;
                case 'f': *((char*)ptr2++) = '\f'; break;
                case 'n': *((char*)ptr2++) = '\n'; break;
                case 'r': *((char*)ptr2++) = '\r'; break;
                case 't': *((char*)ptr2++) = '\t'; break;
                default: *((char*)ptr2++) = *ptr; break;
            }
            ptr++;
        }
    }
    *((char*)ptr2) = '\0';
    if (*ptr == '\"') ptr++;
    item->valuestring = out;
    item->type = cJSON_String;
    return ptr;
}

static const char *parse_array(cJSON *item, const char **value)
{
    cJSON *child;
    const char *ptr = *value;

    if (*ptr != '[') return NULL;
    item->type = cJSON_Array;
    ptr = skip_whitespace(ptr + 1);
    if (*ptr == ']') { *value = ptr + 1; return ptr + 1; }

    item->child = child = cJSON_New_Item();
    if (!child) return NULL;
    *value = skip_whitespace(ptr);
    ptr = (const char*)parse_value(value);
    if (!ptr) return NULL;

    while (*(*value) == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        *value = skip_whitespace((*value) + 1);
        ptr = (const char*)parse_value(value);
        if (!ptr) return NULL;
    }

    if (*(*value) == ']') { (*value)++; return *value; }
    return NULL;
}

static const char *parse_object(cJSON *item, const char **value)
{
    cJSON *child;
    const char *ptr = *value;

    if (*ptr != '{') return NULL;
    item->type = cJSON_Object;
    ptr = skip_whitespace(ptr + 1);
    if (*ptr == '}') { *value = ptr + 1; return ptr + 1; }

    item->child = child = cJSON_New_Item();
    if (!child) return NULL;
    *value = skip_whitespace(ptr);
    ptr = parse_string(child, *value);
    if (!ptr) return NULL;
    child->string = child->valuestring;
    child->valuestring = NULL;
    *value = skip_whitespace(ptr);
    if (*(*value) != ':') return NULL;
    *value = skip_whitespace((*value) + 1);
    ptr = (const char*)parse_value(value);
    if (!ptr) return NULL;

    while (*(*value) == ',') {
        cJSON *new_item = cJSON_New_Item();
        if (!new_item) return NULL;
        child->next = new_item;
        new_item->prev = child;
        child = new_item;
        *value = skip_whitespace((*value) + 1);
        ptr = parse_string(child, *value);
        if (!ptr) return NULL;
        child->string = child->valuestring;
        child->valuestring = NULL;
        *value = skip_whitespace(ptr);
        if (*(*value) != ':') return NULL;
        *value = skip_whitespace((*value) + 1);
        ptr = (const char*)parse_value(value);
        if (!ptr) return NULL;
    }

    if (*(*value) == '}') { (*value)++; return *value; }
    return NULL;
}

static cJSON *parse_value(const char **value)
{
    cJSON *item = cJSON_New_Item();
    if (!item) return NULL;

    *value = skip_whitespace(*value);

    if (!strncmp(*value, "null", 4)) { item->type = cJSON_NULL; *value += 4; }
    else if (!strncmp(*value, "false", 5)) { item->type = cJSON_False; *value += 5; }
    else if (!strncmp(*value, "true", 4)) { item->type = cJSON_True; *value += 4; }
    else if (**value == '\"') { if (!parse_string(item, *value)) { cJSON_Delete(item); return NULL; } *value = skip_whitespace(*value); while (**value && **value != '\"') (*value)++; if (**value == '\"') (*value)++; }
    else if (**value == '-' || (**value >= '0' && **value <= '9')) { *value = parse_number(item, *value); }
    else if (**value == '[') { if (!parse_array(item, value)) { cJSON_Delete(item); return NULL; } }
    else if (**value == '{') { if (!parse_object(item, value)) { cJSON_Delete(item); return NULL; } }
    else { cJSON_Delete(item); return NULL; }

    *value = skip_whitespace(*value);
    return item;
}

cJSON *cJSON_Parse(const char *value)
{
    const char *ptr = value;
    return parse_value(&ptr);
}
