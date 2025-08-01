// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2024 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

func (c *Client) ConfdbGetViaView(viewID string, requests []string) (changeID string, err error) {
	query := url.Values{}
	query.Add("keys", strings.Join(requests, ","))
	endpoint := fmt.Sprintf("/v2/confdb/%s", viewID)

	return c.doAsync("GET", endpoint, query, nil, nil)
}

func (c *Client) ConfdbSetViaView(viewID string, requestValues map[string]any) (changeID string, err error) {
	body, err := json.Marshal(requestValues)
	if err != nil {
		return "", err
	}

	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"

	endpoint := fmt.Sprintf("/v2/confdb/%s", viewID)
	return c.doAsync("PUT", endpoint, nil, headers, bytes.NewReader(body))
}
