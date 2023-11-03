#include "cJSON.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Look up a card on scryfall.com

typedef struct {
  char *str;
  size_t len;
} ScryString;

typedef struct {
  size_t num_responses;
  cJSON *responses[];
} ScryResponses;

typedef struct {
  ScryString query;
  ScryResponses *responses;
} ScrySession;

static inline ScryResponses *add_scry_response(ScryResponses *responses) {
  size_t new_size =
      sizeof(ScryResponses) + sizeof(cJSON *) * (responses->num_responses + 1);
  ScryResponses *new_responses = realloc(responses, new_size);
  if (!new_responses)
    return NULL;
  new_responses->num_responses++;
  return new_responses;
}

static inline int _isalnum(char c) {
  return (c >= 'a' & c <= 'z') | (c >= 'A' & c <= 'Z') | (c >= '0' & c <= '9');
}

static inline ScryString url_encode(ScryString url, char **error) {
  char *str = url.str;
  char *enc, *p, *c;
  int len = 0;

  if (!str)
    return *error = "url_encode: NULL string", (ScryString){NULL, 0};

  // Calculate the new length
  for (c = str; *c; c++) {
    if (_isalnum(*c) || *c == '-' || *c == '_' || *c == '.' || *c == '~') {
      len++;
    } else {
      len += 3;
    }
  }

  enc = malloc(len + 1);
  if (!enc)
    return *error = "url_encode: Out of Memory.", (ScryString){NULL, 0};

  // Escape the string into the new buffer
  for (c = str, p = enc; *c; c++) {
    if (_isalnum(*c) || *c == '-' || *c == '_' || *c == '.' || *c == '~') {
      *p++ = *c;
    } else {
      sprintf(p, "%%%02X", (unsigned char)*c);
      p += 3;
    }
  }

  *p = '\0';
  return *error = NULL, (ScryString){enc, len};
}

static inline cJSON *get_json_response(ScryString url, char **error) {

  char *curl_prefix = "curl -Ls ";
  size_t req_sz = strlen(curl_prefix) + url.len;
  char *curl_cmd = malloc(req_sz + 1);
  strcpy(curl_cmd, curl_prefix);
  strcat(curl_cmd, url.str);

  // Call curl, get the response
  FILE *fp = popen(curl_cmd, "r");
  free(curl_cmd);
  if (!fp)
    return *error = "make_request: Unable to popen() curl.", NULL;

  size_t response_cap = 4096 * 64;
  size_t response_len = 0;
  char *response = malloc(response_cap);

  ssize_t read_ret = 0;
  while ((read_ret = fread(response + response_len, 1, 4096, fp))) {
    if (ferror(fp)) {
      free(response);
      return *error = "make_request: Unexpected read() error.", NULL;
    }
    response_len += read_ret;
    if (response_len + 4096 > response_cap) {
      response_cap *= 2;
      response = realloc(response, response_cap);
    }
  }
  *(response + response_len) = '\0';
  pclose(fp);

  // Parse response
  cJSON *root = cJSON_ParseWithLength(response, response_len);
  if (!root)
    return *error = (char *)cJSON_GetErrorPtr(), NULL;

  // Check if the response is an error response.
  cJSON *error_field = cJSON_GetObjectItemCaseSensitive(root, "object");
  if (!error_field || !cJSON_IsString(error_field) ||
      !strcmp(error_field->valuestring, "error")) {
    // Check if the error is "Your query didn’t match any cards." If so,
    // substitute an empty response.
    cJSON *details_field = cJSON_GetObjectItemCaseSensitive(root, "details");
    if (details_field && cJSON_IsString(details_field) &&
        strstr(details_field->valuestring, "didn’t match any cards") != NULL) {
      cJSON_Delete(root);
      return *error = NULL, cJSON_Parse("{\"object\":\"list\","
                                        "\"total_cards\":0,"
                                        "\"has_more\":false,"
                                        "\"data\":[]}");
    } else {
      cJSON_Delete(root);
      return *error = "make_request: Unexpected/error response.", NULL;
    }
  }

  return root;
}

static inline ScrySession *open_session(ScryString query, char **error) {
  ScryString query_encoded = url_encode(query, error);
  if (*error)
    return *error = NULL, NULL;

  const char *request_url = "https://api.scryfall.com/cards/search?q=";
  size_t full_len = strlen(request_url) + query_encoded.len;
  char *full_url = malloc(full_len + 1);
  strcpy(full_url, request_url);
  strcat(full_url, query_encoded.str);
  free(query_encoded.str);

  cJSON *root = get_json_response((ScryString){full_url, full_len}, error);
  if (*error)
    return NULL;

  // Create session
  ScrySession *session = (ScrySession *)malloc(sizeof(ScrySession));
  if (!session)
    return *error = "open_session: Out of Memory.", cJSON_Delete(root), NULL;
  ScryResponses *responses =
      (ScryResponses *)malloc(sizeof(ScryResponses) + sizeof(cJSON *));
  if (!responses)
    return *error = "open_session: Out of Memory.", cJSON_Delete(root),
           free(session), NULL;

  responses->num_responses = 1;
  responses->responses[0] = root;
  session->query = query;
  session->responses = responses;
  return *error = NULL, session;
}

static inline void next_response(ScrySession *session, char **error) {
  // Check if has "has_mode": true, and if so return a new session.
  // Otherwise, return NULL.
  cJSON *last_response =
      session->responses->responses[session->responses->num_responses - 1];
  cJSON *next_page_field =
      cJSON_GetObjectItemCaseSensitive(last_response, "next_page");
  cJSON_bool has_next_page = cJSON_IsString(next_page_field);
  char *next_page_url = has_next_page ? next_page_field->valuestring : NULL;
  if (next_page_url) {
    cJSON *resp = get_json_response(
        (ScryString){next_page_url, strlen(next_page_url)}, error);
    if (*error)
      return;
    ScryResponses *new_responses = add_scry_response(session->responses);
    if (!new_responses) {
      *error = "next_response: Out of Memory.", cJSON_Delete(resp);
      return;
    }
    session->responses = new_responses;
  }
}

static inline void display_session(ScrySession *session) {
  ScryResponses *responses = session->responses;
  cJSON *last_response = responses->responses[responses->num_responses - 1];

  // First, make sure that scryfall returned a list.
  cJSON *object_field =
      cJSON_GetObjectItemCaseSensitive(last_response, "object");
  cJSON_bool isstring = 0;
  if (!object_field || !(isstring = cJSON_IsString(object_field)) ||
      strcmp(object_field->valuestring, "list")) {
    const char *msg =
        object_field ? (isstring ? "Error: Expected a list of cards, got %s\n"
                                 : "Error: Expected a string, got some other "
                                   "type of json object.%s\n")
                     : "Error: Expected an object field, but no such field was "
                       "present on the response.%s\n";
    char *arg = object_field ? (isstring ? object_field->valuestring : "") : "";
    printf(msg, arg);
    return;
  }

  // Iterate over the cards in the last response
  cJSON *data_field = cJSON_GetObjectItemCaseSensitive(last_response, "data");
  if (!cJSON_IsArray(data_field)) {
    printf("Error: Expected a list of cards, got a non-array data field.\n");
    return;
  }

  for (cJSON *card = data_field->child; card; card = card->next) {
    cJSON *name_field = cJSON_GetObjectItemCaseSensitive(card, "name");
    if (!cJSON_IsString(name_field)) {
      printf("Error: Expected a string for the name field, got a non-string "
             "value.\n");
      return;
    }
    printf("%s\n", name_field->valuestring);
  }
}

int main(int argc, char **argv) {

  if (argc == 1) {
    printf("Usage: scry <scryfall query>\n");
    return 1;
  }

  // Join the arguments into a single string
  size_t total_len = argc;
  for (int i = 1; i < argc; i++)
    total_len += strlen(argv[i]);

  char *query = malloc(total_len);
  query[0] = '\0';
  for (int i = 1; i < argc; i++) {
    i != 1 ? strcat(query, " "), total_len++ : 0;
    strcat(query, argv[i]), total_len += strlen(argv[i]);
  }
  ScryString query_str = {query, total_len};

  char *errmsg = NULL;
  ScrySession *session = open_session(query_str, &errmsg);
  if (errmsg) {
    printf("Error: %s\n", errmsg);
    return 1;
  }

  printf("Query: %s\n", query);
  char *json = cJSON_Print(session->responses->responses[0]);
  printf("Response: %s\n", json);
  next_response(session, &errmsg);
  display_session(session);
  fflush(stdout);
}
