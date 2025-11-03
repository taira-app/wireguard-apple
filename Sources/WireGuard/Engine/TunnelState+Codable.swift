// SPDX-License-Identifier: LGPL-3.0-only OR LicenseRef-Taira-Commercial
// Copyright (c) 2025 Taira. All rights reserved.

import Foundation

// MARK: - Codable conformance

extension TunnelState: Codable {
	private enum CodingKeys: String, CodingKey {
		case type
		case errorMessage
	}

	private enum StateType: String, Codable {
		case stopped
		case starting
		case connected
		case stopping
		case reasserting
		case error
	}

	public init(from decoder: Decoder) throws {
		let container = try decoder.container(keyedBy: CodingKeys.self)
		let type = try container.decode(StateType.self, forKey: .type)

		switch type {
		case .stopped:
			self = .stopped
		case .starting:
			self = .starting
		case .connected:
			self = .connected
		case .stopping:
			self = .stopping
		case .reasserting:
			self = .reasserting
		case .error:
			let message = try container.decode(String.self, forKey: .errorMessage)
			self = .error(message)
		}
	}

	public func encode(to encoder: Encoder) throws {
		var container = encoder.container(keyedBy: CodingKeys.self)

		switch self {
		case .stopped:
			try container.encode(StateType.stopped, forKey: .type)
		case .starting:
			try container.encode(StateType.starting, forKey: .type)
		case .connected:
			try container.encode(StateType.connected, forKey: .type)
		case .stopping:
			try container.encode(StateType.stopping, forKey: .type)
		case .reasserting:
			try container.encode(StateType.reasserting, forKey: .type)
		case .error(let message):
			try container.encode(StateType.error, forKey: .type)
			try container.encode(message, forKey: .errorMessage)
		}
	}
}
