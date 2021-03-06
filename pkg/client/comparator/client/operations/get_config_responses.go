// Code generated by go-swagger; DO NOT EDIT.

// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package operations

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/trustbloc/ace/pkg/client/comparator/models"
)

// GetConfigReader is a Reader for the GetConfig structure.
type GetConfigReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetConfigReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewGetConfigOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewGetConfigInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result
	default:
		return nil, runtime.NewAPIError("response status code does not match any response statuses defined for this endpoint in the swagger spec", response, response.Code())
	}
}

// NewGetConfigOK creates a GetConfigOK with default headers values
func NewGetConfigOK() *GetConfigOK {
	return &GetConfigOK{}
}

/* GetConfigOK describes a response with status code 200, with default header values.

The comparator's configuration.
*/
type GetConfigOK struct {
	Payload *models.Config
}

func (o *GetConfigOK) Error() string {
	return fmt.Sprintf("[GET /config][%d] getConfigOK  %+v", 200, o.Payload)
}
func (o *GetConfigOK) GetPayload() *models.Config {
	return o.Payload
}

func (o *GetConfigOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Config)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}

// NewGetConfigInternalServerError creates a GetConfigInternalServerError with default headers values
func NewGetConfigInternalServerError() *GetConfigInternalServerError {
	return &GetConfigInternalServerError{}
}

/* GetConfigInternalServerError describes a response with status code 500, with default header values.

Generic Error
*/
type GetConfigInternalServerError struct {
	Payload *models.Error
}

func (o *GetConfigInternalServerError) Error() string {
	return fmt.Sprintf("[GET /config][%d] getConfigInternalServerError  %+v", 500, o.Payload)
}
func (o *GetConfigInternalServerError) GetPayload() *models.Error {
	return o.Payload
}

func (o *GetConfigInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.Error)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
