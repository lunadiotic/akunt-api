<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class AuthController extends Controller
{
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => ['required', 'email'],
            'password' => ['required']
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        try {
            $user = User::where('email', $request->email)->first();

            if (! $user || ! Hash::check($request->password, $user->password)) {
                return response([
                    'message' => ['These credentials do not match our records.']
                ], 422);
            }

            $explodeToken = explode(
                "|",
                $user->createToken('token')->plainTextToken
            );

            return response()->json([
                'message' => 'Auth success',
                'data' => [
                    'user' => $user,
                    'token' => $explodeToken[1]
                ]
            ]);
        } catch (Exception $e) {
            return response()->json([
                'message' => "Failed " . $e->getMessage()
            ], 409);
        }
    }
}
