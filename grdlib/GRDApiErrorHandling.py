# (C) Copyright IBM Corp. 2018 All Rights Reserved


RESPONSE_CODE_SUCCESS = 200
RESPONSE_HTTP_SUCCESS = '<Response [200]>'
RESPONSE_CODE_SUCCESS_CREATED = 201
RESPONSE_CODE_SUCCESS_ACCEPTED = 202
RESPONSE_CODE_SUCCESS_NO_CONTENT = 204

valid_codes = (RESPONSE_CODE_SUCCESS,
               RESPONSE_HTTP_SUCCESS,
               RESPONSE_CODE_SUCCESS_CREATED,
               RESPONSE_CODE_SUCCESS_ACCEPTED,
               RESPONSE_CODE_SUCCESS_NO_CONTENT)


class GuardiumApiError(Exception):
    def __init__(self, message, error_code=0):
        super(GuardiumApiError, self).__init__(message)
        self.error_code = error_code

    def __str__(self):
         return 'ErrorCode: ' + str(self.error_code) + ", ErrorMessage: " + self.message


class GuardiumApiInvalidParamsError(GuardiumApiError):

    def __init__(self, message, valid_parameter_values, error_code=0):
        super(GuardiumApiInvalidParamsError, self).__init__(message, error_code)
        self.valid_parameter_values = valid_parameter_values

    def __str__(self):
        result_str = super(GuardiumApiInvalidParamsError, self).__str__()
        if not (self.valid_parameter_values is None) and isinstance(self.valid_parameter_values, list) and len(self.valid_parameter_values) > 0:
            all_values = "'" + "', '".join(self.valid_parameter_values)
            return result_str + ", ValidParameterValues: " + all_values + "'."
        else:
            return result_str

    def get_valid_parameter_values(self):
        return self.valid_parameter_values


def check_for_invalid_response(response):
    if response.status_code not in valid_codes:
        error_message = response.content.splitlines()[0]
        error_code = str(response)
        raise GuardiumApiError(error_message, error_code)
    elif type(response.json()) is dict:
        if len(response.json()) == 2:
            if 'Message' in response.json() and response.json()['Message'] == "No More Records Found":
                raise StopIteration
            elif 'ErrorMessage' in response.json() and 'ErrorCode' in response.json():
                raise GuardiumApiError(response.json()['ErrorMessage'], response.json()['ErrorCode'])
        elif len(response.json()) == 3:
            if 'ErrorMessage' in response.json() and 'ErrorCode' in response.json() and 'ValidParameterValues' in response.json():
                raise GuardiumApiInvalidParamsError(response.json()['ErrorMessage'], response.json()['ValidParameterValues'], response.json()['ErrorCode'])
