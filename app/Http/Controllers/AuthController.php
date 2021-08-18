<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Carbon\Carbon;
use Illuminate\Support\Facades\Password;
use Illuminate\Support\Str;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\Rules\Password as RulesPassword;


class AuthController extends Controller
{
    public function register (Request $request) {

        $request->validate([
            'name' => 'required|string',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed|min:8',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        $user->save();
        $accessToken = $user->createToken('User Access Token')->accessToken;

        $response = [
            'access_token' => $accessToken,
            'user' => $user,
        ];
        return response()->json($response);
    }

    public function login (Request $request) {

        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        $credentials = $request->only(['email', 'password']);
        if(!Auth::attempt($credentials)) {
            return response()->json([
                'message' => 'Invalid username or password.'
            ], 401);
        }

        $user = $request->user();
        $tokenResult = $user->createToken('User Access Token');
        $accessToken = $tokenResult->accessToken;

        $response = [
            'access_token' => $accessToken,
            'token_type' => 'bearer',
            'expires_in' => Carbon::parse($tokenResult->token->expires_at)->toDateTimeString(),
            'user' => auth()->user(),
        ];
        return response()->json($response);
    }

    public function resetPassword(Request $request) {

        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => ['required', 'confirmed', RulesPassword::defaults()],
        ]);

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user) use ($request) {
                $user->forceFill([
                    'password' => Hash::make($request->password),
                    'remember_token' => Str::random(60),
                ])->save();
                $user->tokens()->delete();
                event(new PasswordReset($user));
            }
        );

        if ($status == Password::PASSWORD_RESET) {
            return response()->json([
                'message'=> __($status)
            ], 201);
        }

        return response()->json([
            'message'=> __($status)
        ], 500);

    }

    public function forgotPassword(Request $request) {

        $request->validate([
            'email' => 'required|email',
        ]);

        $status = Password::sendResetLink(
            $request->only('email')
        );

        if ($status == Password::RESET_LINK_SENT) {
            return response()->json([
                'status' => __($status)
            ], 201);
        }

    }

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }

}
