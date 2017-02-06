defmodule ExAws.CloudFront.CannedPolicyTest do
  use ExUnit.Case, async: true

  alias ExAws.CloudFront.Policy
  alias ExAws.CloudFront.CannedPolicy

  test "should fail if `expire_time` is after the end of time" do
    result =
      CannedPolicy.new("http://t.com", 3000000000000)
      |> Policy.to_statement
    assert result == {:error, "`expire_time` must be less than 2147483647 (January 19, 2038 03:14:08 GMT)"}
  end

  test "should fail if `expire_time` is before now" do
    result =
      CannedPolicy.new("http://t.com", ExAws.Utils.now_in_seconds - 10000)
      |> Policy.to_statement
    assert result == {:error, "`expire_time` must be after the current time"}
  end

  test "should return the canned policy statement" do
    url = "http://t.com"
    expire_time = ExAws.Utils.now_in_seconds + 10000
    policy = CannedPolicy.new url, expire_time

    assert {:ok, result} = Policy.to_statement(policy)
    assert %{
      "Statement" => [%{
        "Resource" => ^url,
        "Condition" => %{
          "DateLessThan" => %{
            "AWS:EpochTime" => ^expire_time
          }
        },
      }]
    } = result
  end
end
