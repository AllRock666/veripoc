from unittest.mock import patch, MagicMock
from lab.seed import seed_juice_shop, DEFAULT_CANARY


def test_seed_juice_shop_mocked():
    with patch("requests.Session") as mock_session_cls:
        session = MagicMock()
        mock_session_cls.return_value = session

        # 1. Security questions response
        sq_mock = MagicMock()
        sq_mock.json.return_value = {"status": "success", "data": [{"id": 42}]}
        session.get.return_value = sq_mock

        # Responses for POST
        # Post user A: 201
        # Post user B: 201
        # Login user A: 200
        # Login user B: 200
        # Post Address: 201
        # Post BasketItem: 200
        login_a = MagicMock()
        login_a.status_code = 200
        login_a.json.return_value = {"authentication": {"token": "token_a_jwt", "bid": 101}}

        login_b = MagicMock()
        login_b.status_code = 200
        login_b.json.return_value = {"authentication": {"token": "token_b_jwt", "bid": 102}}

        addr_res = MagicMock()
        addr_res.status_code = 201
        addr_res.json.return_value = {"status": "success", "data": {"id": 55}}

        basket_item_res = MagicMock()
        basket_item_res.status_code = 200

        user_create_res = MagicMock()
        user_create_res.status_code = 201

        session.post.side_effect = [
            user_create_res,  # register User A
            user_create_res,  # register User B
            login_a,          # login User A
            login_b,          # login User B
            addr_res,         # add address for User B
            basket_item_res,  # add basket item for User B
        ]

        data = seed_juice_shop(
            target_url="http://test-juice:3000",
            canary_value="CANARY_TEST_123",
        )

        assert data["canary_value"] == "CANARY_TEST_123"
        assert data["user_a"]["token"] == "token_a_jwt"
        assert data["user_a"]["bid"] == 101
        assert data["user_b"]["token"] == "token_b_jwt"
        assert data["user_b"]["bid"] == 102
        assert data["user_b"]["address_id"] == 55

        # Check that session.post was called with the canary string in address creation
        called_addr_kwargs = session.post.call_args_list[4]
        assert called_addr_kwargs[1]["headers"]["Authorization"] == "Bearer token_b_jwt"
        assert called_addr_kwargs[1]["json"]["streetAddress"] == "CANARY_TEST_123"
